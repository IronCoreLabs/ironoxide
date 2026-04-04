package ironoxide

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// --- Test infrastructure (mirrors tests/common.rs) ---

type testConfig struct {
	ProjectID              uint32 `json:"projectId"`
	SegmentID              string `json:"segmentId"`
	IdentityAssertionKeyID uint32 `json:"identityAssertionKeyId"`
}

var (
	config    testConfig
	pemKey    *ecdsa.PrivateKey
	configErr error
)

func init() {
	env := os.Getenv("IRONCORE_ENV")
	suffix := "-prod"
	if env == "stage" {
		suffix = "-stage"
	}

	// Find testkeys relative to repo root
	repoRoot := findRepoRoot()
	configPath := filepath.Join(repoRoot, "tests", "testkeys", fmt.Sprintf("ironcore-config%s.json", suffix))
	pemPath := filepath.Join(repoRoot, "tests", "testkeys", fmt.Sprintf("iak%s.pem", suffix))

	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		configErr = fmt.Errorf("failed to read config %s: %w", configPath, err)
		return
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		configErr = fmt.Errorf("failed to parse config: %w", err)
		return
	}

	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		configErr = fmt.Errorf("failed to read PEM %s: %w", pemPath, err)
		return
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		configErr = fmt.Errorf("failed to decode PEM block")
		return
	}
	// Try PKCS8 first (common format), fall back to SEC1
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try SEC1 format
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			configErr = fmt.Errorf("failed to parse EC key: %w", err)
			return
		}
	}
	ecKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		configErr = fmt.Errorf("key is not ECDSA")
		return
	}
	pemKey = ecKey
}

func findRepoRoot() string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func skipIfNoConfig(t *testing.T) {
	t.Helper()
	if configErr != nil {
		t.Skipf("integration test infrastructure not available: %v", configErr)
	}
}

const userPassword = "foo"

func genJWT(t *testing.T, accountID string) string {
	t.Helper()
	now := time.Now().Unix()

	// Build JWT header
	header := base64URLEncode([]byte(`{"alg":"ES256","typ":"JWT"}`))

	// Build JWT claims
	claims := fmt.Sprintf(
		`{"sub":"%s","iat":%d,"exp":%d,"pid":%d,"sid":"%s","kid":%d}`,
		accountID, now, now+120, config.ProjectID, config.SegmentID, config.IdentityAssertionKeyID,
	)
	payload := base64URLEncode([]byte(claims))

	// Sign
	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, pemKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}

	// Encode r and s as fixed-size 32-byte big-endian values
	curveBits := pemKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keyBytes)
	copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sig[2*keyBytes-len(sBytes):], sBytes)

	signature := base64URLEncode(sig)
	return signingInput + "." + signature
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func uniqueID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s%x", prefix, b)
}

func createUserAndDevice(t *testing.T) (*BlockingIronOxide, string) {
	t.Helper()
	accountID := uniqueID("gotest-")

	jwt := genJWT(t, accountID)
	jwtObj, err := NewJwt(jwt)
	if err != nil {
		t.Fatalf("failed to create JWT: %v", err)
	}

	// Create user
	_, err = BlockingUserCreate(jwtObj, userPassword, NewUserCreateOpts(false), nil)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Generate device
	device, err := BlockingGenerateNewDevice(jwtObj, userPassword, NewDeviceCreateOpts(nil), nil)
	if err != nil {
		t.Fatalf("failed to generate device: %v", err)
	}

	// Build DeviceContext and initialize
	ctx := NewDeviceContext(
		UserId(device.AccountId()),
		device.SegmentId(),
		device.DevicePrivateKey(),
		device.SigningPrivateKey(),
	)
	blockingCtx := NewBlockingDeviceContext(ctx)

	caching := NewPolicyCachingConfig(128)
	timeout := uint64(30000)
	config := NewIronOxideConfig(caching, &timeout)

	sdk, err := BlockingInitialize(blockingCtx, config)
	if err != nil {
		t.Fatalf("failed to initialize SDK: %v", err)
	}

	return sdk, accountID
}

// --- Integration tests ---

func TestIntegrationUserVerify(t *testing.T) {
	skipIfNoConfig(t)
	accountID := uniqueID("gotest-")
	jwt := genJWT(t, accountID)
	jwtObj, err := NewJwt(jwt)
	if err != nil {
		t.Fatalf("JWT creation failed: %v", err)
	}

	// Verify non-existing user returns nil
	result, err := BlockingUserVerify(jwtObj, nil)
	if err != nil {
		t.Fatalf("user_verify failed: %v", err)
	}
	if result != nil {
		t.Error("expected nil for non-existing user")
	}
}

func TestIntegrationUserCreateAndVerify(t *testing.T) {
	skipIfNoConfig(t)
	accountID := uniqueID("gotest-")
	jwt := genJWT(t, accountID)
	jwtObj, err := NewJwt(jwt)
	if err != nil {
		t.Fatalf("JWT creation failed: %v", err)
	}

	// Create user
	createResult, err := BlockingUserCreate(jwtObj, userPassword, NewUserCreateOpts(false), nil)
	if err != nil {
		t.Fatalf("user_create failed: %v", err)
	}
	if len(createResult.UserPublicKey()) == 0 {
		t.Error("expected non-empty public key")
	}
	if createResult.NeedsRotation() {
		t.Error("expected needs_rotation=false")
	}

	// Verify user exists
	jwtObj2, _ := NewJwt(genJWT(t, accountID))
	verifyResult, err := BlockingUserVerify(jwtObj2, nil)
	if err != nil {
		t.Fatalf("user_verify failed: %v", err)
	}
	if verifyResult == nil || *verifyResult == nil {
		t.Fatal("expected non-nil verify result for existing user")
	}
	if string((*verifyResult).AccountId()) != accountID {
		t.Errorf("expected account_id=%s, got %s", accountID, (*verifyResult).AccountId())
	}
}

func TestIntegrationDocumentEncryptDecryptRoundtrip(t *testing.T) {
	skipIfNoConfig(t)
	sdk, _ := createUserAndDevice(t)

	plaintext := []byte("hello from Go integration tests!")

	// Encrypt to self
	opts := DocumentEncryptOptsWithExplicitGrants(nil, nil, true, nil)
	encResult, err := sdk.DocumentEncrypt(plaintext, opts)
	if err != nil {
		t.Fatalf("document_encrypt failed: %v", err)
	}
	if string(encResult.Id()) == "" {
		t.Error("expected non-empty document ID")
	}
	if len(encResult.EncryptedData()) == 0 {
		t.Error("expected non-empty encrypted data")
	}

	// Decrypt
	decResult, err := sdk.DocumentDecrypt(encResult.EncryptedData())
	if err != nil {
		t.Fatalf("document_decrypt failed: %v", err)
	}
	if string(decResult.DecryptedData()) != string(plaintext) {
		t.Errorf("decrypted data mismatch: got %q, want %q", decResult.DecryptedData(), plaintext)
	}
}

func TestIntegrationDocumentList(t *testing.T) {
	skipIfNoConfig(t)
	sdk, _ := createUserAndDevice(t)

	// Encrypt a document first
	opts := DocumentEncryptOptsWithExplicitGrants(nil, nil, true, nil)
	_, err := sdk.DocumentEncrypt([]byte("test data"), opts)
	if err != nil {
		t.Fatalf("document_encrypt failed: %v", err)
	}

	// List documents
	listResult, err := sdk.DocumentList()
	if err != nil {
		t.Fatalf("document_list failed: %v", err)
	}
	if len(listResult.Result()) == 0 {
		t.Error("expected at least one document in list")
	}
}

func TestIntegrationDocumentGetMetadata(t *testing.T) {
	skipIfNoConfig(t)
	sdk, _ := createUserAndDevice(t)

	docName := DocumentName("my-test-doc")
	opts := DocumentEncryptOptsWithExplicitGrants(nil, &docName, true, nil)
	encResult, err := sdk.DocumentEncrypt([]byte("metadata test"), opts)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	meta, err := sdk.DocumentGetMetadata(encResult.Id())
	if err != nil {
		t.Fatalf("get_metadata failed: %v", err)
	}
	if meta.Id() != encResult.Id() {
		t.Errorf("ID mismatch: got %s, want %s", meta.Id(), encResult.Id())
	}
	if meta.Name() == nil || *meta.Name() != "my-test-doc" {
		t.Errorf("expected name=my-test-doc, got %v", meta.Name())
	}
}

func TestIntegrationGroupCreateAndList(t *testing.T) {
	skipIfNoConfig(t)
	sdk, _ := createUserAndDevice(t)

	groupName := GroupName("go-test-group")
	opts := NewGroupCreateOpts(nil, &groupName, true, true, nil, []UserId{}, []UserId{}, false)
	createResult, err := sdk.GroupCreate(opts)
	if err != nil {
		t.Fatalf("group_create failed: %v", err)
	}
	if string(createResult.Id()) == "" {
		t.Error("expected non-empty group ID")
	}
	if createResult.Name() == nil || *createResult.Name() != "go-test-group" {
		t.Errorf("expected name=go-test-group, got %v", createResult.Name())
	}
	if !createResult.IsAdmin() {
		t.Error("expected is_admin=true")
	}
	if !createResult.IsMember() {
		t.Error("expected is_member=true")
	}

	// List groups
	listResult, err := sdk.GroupList()
	if err != nil {
		t.Fatalf("group_list failed: %v", err)
	}
	if len(listResult.Result()) == 0 {
		t.Error("expected at least one group")
	}
}

func TestIntegrationEncryptToGroup(t *testing.T) {
	skipIfNoConfig(t)
	sdk, _ := createUserAndDevice(t)

	// Create a group
	opts := NewGroupCreateOpts(nil, nil, true, true, nil, []UserId{}, []UserId{}, false)
	group, err := sdk.GroupCreate(opts)
	if err != nil {
		t.Fatalf("group_create failed: %v", err)
	}

	// Encrypt to the group
	encOpts := DocumentEncryptOptsWithExplicitGrants(nil, nil, false, []UserOrGroup{
		UserOrGroupGroup{Id: group.Id()},
	})
	encResult, err := sdk.DocumentEncrypt([]byte("group encrypted data"), encOpts)
	if err != nil {
		t.Fatalf("encrypt to group failed: %v", err)
	}

	// Decrypt (user is a member of the group)
	decResult, err := sdk.DocumentDecrypt(encResult.EncryptedData())
	if err != nil {
		t.Fatalf("decrypt from group failed: %v", err)
	}
	if string(decResult.DecryptedData()) != "group encrypted data" {
		t.Errorf("decrypted data mismatch")
	}
}

func TestIntegrationGrantAndRevokeAccess(t *testing.T) {
	skipIfNoConfig(t)
	sdk, accountID := createUserAndDevice(t)

	// Encrypt
	opts := DocumentEncryptOptsWithExplicitGrants(nil, nil, true, nil)
	encResult, err := sdk.DocumentEncrypt([]byte("access test"), opts)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Grant access to self (already have it, but tests the API path)
	grantResult, err := sdk.DocumentGrantAccess(encResult.Id(), []UserOrGroup{
		UserOrGroupUser{Id: UserId(accountID)},
	})
	if err != nil {
		t.Fatalf("grant_access failed: %v", err)
	}
	// The user already had access, so this should succeed with the user in succeeded list
	_ = grantResult

	// Revoke own access
	revokeResult, err := sdk.DocumentRevokeAccess(encResult.Id(), []UserOrGroup{
		UserOrGroupUser{Id: UserId(accountID)},
	})
	if err != nil {
		t.Fatalf("revoke_access failed: %v", err)
	}
	if len(revokeResult.Succeeded()) == 0 {
		t.Error("expected at least one successful revocation")
	}

	// Decrypt should now fail
	_, err = sdk.DocumentDecrypt(encResult.EncryptedData())
	if err == nil {
		t.Error("expected error after revoking own access")
	}
}

func TestIntegrationUserListDevices(t *testing.T) {
	skipIfNoConfig(t)
	sdk, _ := createUserAndDevice(t)

	devices, err := sdk.UserListDevices()
	if err != nil {
		t.Fatalf("user_list_devices failed: %v", err)
	}
	if len(devices.Result()) == 0 {
		t.Error("expected at least one device")
	}
	foundCurrent := false
	for _, d := range devices.Result() {
		if d.Id() == 0 {
			t.Error("expected non-zero device ID")
		}
		if d.IsCurrentDevice() {
			foundCurrent = true
		}
	}
	if !foundCurrent {
		t.Error("expected to find current device in list")
	}
}

func TestIntegrationInitializeCheckRotation(t *testing.T) {
	skipIfNoConfig(t)
	accountID := uniqueID("gotest-")
	jwt := genJWT(t, accountID)
	jwtObj, _ := NewJwt(jwt)

	BlockingUserCreate(jwtObj, userPassword, NewUserCreateOpts(false), nil)
	jwtObj2, _ := NewJwt(genJWT(t, accountID))
	device, _ := BlockingGenerateNewDevice(jwtObj2, userPassword, NewDeviceCreateOpts(nil), nil)

	ctx := NewDeviceContext(
		UserId(device.AccountId()),
		device.SegmentId(),
		device.DevicePrivateKey(),
		device.SigningPrivateKey(),
	)
	blockingCtx := NewBlockingDeviceContext(ctx)
	caching := NewPolicyCachingConfig(128)
	timeout := uint64(30000)
	config := NewIronOxideConfig(caching, &timeout)

	result, err := BlockingInitializeCheckRotation(blockingCtx, config)
	if err != nil {
		t.Fatalf("initialize_check_rotation failed: %v", err)
	}

	switch result.(type) {
	case BlockingInitResultNoRotationNeeded:
		// expected for a user created without needs_rotation
	case BlockingInitResultRotationNeeded:
		t.Error("did not expect rotation needed for freshly created user")
	default:
		t.Errorf("unexpected result type: %T", result)
	}
}

func TestIntegrationExportAndReinitializeWithCache(t *testing.T) {
	skipIfNoConfig(t)
	accountID := uniqueID("gotest-")
	jwt := genJWT(t, accountID)
	jwtObj, _ := NewJwt(jwt)

	BlockingUserCreate(jwtObj, userPassword, NewUserCreateOpts(false), nil)
	jwtObj2, _ := NewJwt(genJWT(t, accountID))
	device, _ := BlockingGenerateNewDevice(jwtObj2, userPassword, NewDeviceCreateOpts(nil), nil)

	// Build device context — reuse for both init calls
	ctx := NewDeviceContext(
		UserId(device.AccountId()),
		device.SegmentId(),
		device.DevicePrivateKey(),
		device.SigningPrivateKey(),
	)

	caching := NewPolicyCachingConfig(128)
	timeout := uint64(30000)
	conf := NewIronOxideConfig(caching, &timeout)

	// First init to get an SDK and export cache
	blockingCtx := NewBlockingDeviceContext(ctx)
	sdk, err := BlockingInitialize(blockingCtx, conf)
	if err != nil {
		t.Fatalf("first initialize failed: %v", err)
	}

	cache, err := sdk.ExportPublicKeyCache()
	if err != nil {
		t.Fatalf("export_public_key_cache failed: %v", err)
	}
	if len(cache) == 0 {
		t.Fatal("expected non-empty cache")
	}

	// Re-initialize with the same device context and the cached keys
	blockingCtx2 := NewBlockingDeviceContext(ctx)
	_, err = BlockingInitializeWithPublicKeys(blockingCtx2, conf, cache)
	if err != nil {
		t.Fatalf("initialize_with_public_keys failed: %v", err)
	}
}

// Ensure unused imports don't cause issues
var _ = elliptic.P256
var _ = big.NewInt
