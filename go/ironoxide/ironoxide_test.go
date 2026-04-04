package ironoxide

import (
	"testing"
)

// --- Config types ---

func TestPolicyCachingConfigRoundtrip(t *testing.T) {
	config := NewPolicyCachingConfig(256)
	if config.MaxEntries() != 256 {
		t.Errorf("expected max_entries=256, got %d", config.MaxEntries())
	}
}

func TestIronOxideConfigRoundtrip(t *testing.T) {
	caching := NewPolicyCachingConfig(64)
	timeout := uint64(5000)
	config := NewIronOxideConfig(caching, &timeout)

	if config.PolicyCaching().MaxEntries() != 64 {
		t.Errorf("expected policy_caching.max_entries=64, got %d", config.PolicyCaching().MaxEntries())
	}
	millis := config.TimeoutMillis()
	if millis == nil || *millis != 5000 {
		t.Errorf("expected timeout_millis=5000, got %v", millis)
	}
}

func TestIronOxideConfigNilTimeout(t *testing.T) {
	caching := NewPolicyCachingConfig(128)
	config := NewIronOxideConfig(caching, nil)

	if config.TimeoutMillis() != nil {
		t.Errorf("expected nil timeout, got %v", config.TimeoutMillis())
	}
}

// --- Policy types ---

func TestPolicyGrantRoundtrip(t *testing.T) {
	cat := Category("PII")
	sens := Sensitivity("HIGH")
	ds := DataSubject("EMPLOYEE")
	sub := UserId("substitute-user")
	grant := NewPolicyGrant(&cat, &sens, &ds, &sub)

	if grant.Category() == nil || *grant.Category() != "PII" {
		t.Errorf("expected category=PII, got %v", grant.Category())
	}
	if grant.Sensitivity() == nil || *grant.Sensitivity() != "HIGH" {
		t.Errorf("expected sensitivity=HIGH, got %v", grant.Sensitivity())
	}
	if grant.DataSubject() == nil || *grant.DataSubject() != "EMPLOYEE" {
		t.Errorf("expected data_subject=EMPLOYEE, got %v", grant.DataSubject())
	}
	if grant.SubstituteUser() == nil || *grant.SubstituteUser() != "substitute-user" {
		t.Errorf("expected substitute_user=substitute-user, got %v", grant.SubstituteUser())
	}
}

func TestPolicyGrantNilFields(t *testing.T) {
	grant := NewPolicyGrant(nil, nil, nil, nil)

	if grant.Category() != nil {
		t.Errorf("expected nil category")
	}
	if grant.Sensitivity() != nil {
		t.Errorf("expected nil sensitivity")
	}
	if grant.DataSubject() != nil {
		t.Errorf("expected nil data_subject")
	}
	if grant.SubstituteUser() != nil {
		t.Errorf("expected nil substitute_user")
	}
}

// --- User/Device opts ---

func TestUserCreateOpts(t *testing.T) {
	opts := NewUserCreateOpts(true)
	_ = opts
}

func TestDeviceCreateOptsWithName(t *testing.T) {
	name := DeviceName("my-device")
	opts := NewDeviceCreateOpts(&name)
	_ = opts
}

func TestDeviceCreateOptsNilName(t *testing.T) {
	opts := NewDeviceCreateOpts(nil)
	_ = opts
}

// --- ExplicitGrant ---

func TestExplicitGrantConstruction(t *testing.T) {
	grants := []UserOrGroup{
		UserOrGroupUser{Id: UserId("user1")},
		UserOrGroupGroup{Id: GroupId("group1")},
	}
	eg := NewExplicitGrant(true, grants)
	_ = eg
}

// --- DocumentEncryptOpts ---

func TestDocumentEncryptOptsWithExplicitGrants(t *testing.T) {
	docId := DocumentId("doc-123")
	docName := DocumentName("test-doc")
	opts := DocumentEncryptOptsWithExplicitGrants(&docId, &docName, true, []UserOrGroup{
		UserOrGroupUser{Id: UserId("user1")},
	})
	_ = opts
}

func TestDocumentEncryptOptsWithPolicyGrants(t *testing.T) {
	policy := NewPolicyGrant(nil, nil, nil, nil)
	opts := DocumentEncryptOptsWithPolicyGrants(nil, nil, policy)
	_ = opts
}

// --- GroupCreateOpts ---

func TestGroupCreateOpts(t *testing.T) {
	groupId := GroupId("my-group")
	groupName := GroupName("My Group")
	opts := NewGroupCreateOpts(
		&groupId,
		&groupName,
		true,  // add_as_admin
		true,  // add_as_member
		nil,   // owner
		[]UserId{},
		[]UserId{},
		false, // needs_rotation
	)
	_ = opts
}

// --- Jwt ---

func TestJwtRejectsInvalidString(t *testing.T) {
	_, err := NewJwt("not-a-valid-jwt")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

// --- DeviceContext ---

// Uses the same test key material from the Rust test suite (tests/common.rs create_test_device_context).
func testDeviceContext() *DeviceContext {
	privKey := PrivateKey([]byte{
		0x6f, 0x36, 0xf4, 0x46, 0x58, 0x34, 0xbb, 0xb8, 0x31, 0xf7, 0x00, 0xee, 0x93, 0x5a, 0x69, 0x44,
		0x8e, 0xfb, 0x38, 0x7f, 0xf4, 0x7d, 0xea, 0xd7, 0x95, 0xe7, 0xa7, 0x27, 0x70, 0x20, 0xe8, 0x98,
	})
	signingKey := DeviceSigningKeyPair([]byte{
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29,
		148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
	})
	return NewDeviceContext(UserId("account_id"), 22, privKey, signingKey)
}

func TestDeviceContextRoundtrip(t *testing.T) {
	ctx := testDeviceContext()

	if ctx.AccountId() != "account_id" {
		t.Errorf("expected account_id=account_id, got %s", ctx.AccountId())
	}
	if ctx.SegmentId() != 22 {
		t.Errorf("expected segment_id=22, got %d", ctx.SegmentId())
	}
	if len(ctx.DevicePrivateKey()) != 32 {
		t.Errorf("expected 32-byte private key, got %d bytes", len(ctx.DevicePrivateKey()))
	}
	if len(ctx.SigningPrivateKey()) != 64 {
		t.Errorf("expected 64-byte signing key, got %d bytes", len(ctx.SigningPrivateKey()))
	}
}

// --- UserOrGroup enum ---

func TestUserOrGroupVariants(t *testing.T) {
	user := UserOrGroupUser{Id: UserId("alice")}
	group := UserOrGroupGroup{Id: GroupId("engineers")}

	var _ UserOrGroup = user
	var _ UserOrGroup = group

	if user.Id != "alice" {
		t.Errorf("expected user id=alice, got %s", user.Id)
	}
	if group.Id != "engineers" {
		t.Errorf("expected group id=engineers, got %s", group.Id)
	}
}

// --- AssociationType enum ---

func TestAssociationTypeValues(t *testing.T) {
	_ = AssociationTypeOwner
	_ = AssociationTypeFromUser
	_ = AssociationTypeFromGroup
}

// --- BlockingInitResult enum ---

func TestBlockingInitResultVariants(t *testing.T) {
	var _ BlockingInitResult = BlockingInitResultNoRotationNeeded{}
	var _ BlockingInitResult = BlockingInitResultRotationNeeded{}
}

// --- NeedsRotation on UserResult ---

func TestUserResultNeedsRotation(t *testing.T) {
	// Verify the method exists on the type (can't construct UserResult directly)
	var _ func(*UserResult) bool = (*UserResult).NeedsRotation
}

// --- RotateAllResult record ---

func TestRotateAllResultFields(t *testing.T) {
	result := RotateAllResult{
		UserResult:   nil,
		GroupResults: nil,
	}
	if result.UserResult != nil {
		t.Errorf("expected nil user_result")
	}
	if result.GroupResults != nil {
		t.Errorf("expected nil group_results")
	}
}

// --- Error types ---

func TestIronOxideErrFlatError(t *testing.T) {
	err := NewIronOxideErrValidationError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

// --- BlockingDeviceContext from DeviceContext ---

func TestBlockingDeviceContextFromDeviceContext(t *testing.T) {
	ctx := testDeviceContext()
	blocking := NewBlockingDeviceContext(ctx)

	if blocking.AccountId() != "account_id" {
		t.Errorf("expected account_id=account_id, got %s", blocking.AccountId())
	}
	if blocking.SegmentId() != 22 {
		t.Errorf("expected segment_id=22, got %d", blocking.SegmentId())
	}
}

// --- Initialize with bad credentials fails gracefully ---

func TestInitializeWithBadDeviceFails(t *testing.T) {
	ctx := testDeviceContext()
	blockingCtx := NewBlockingDeviceContext(ctx)

	caching := NewPolicyCachingConfig(128)
	timeout := uint64(5000)
	config := NewIronOxideConfig(caching, &timeout)

	_, err := BlockingInitialize(blockingCtx, config)
	if err == nil {
		t.Error("expected error when initializing with invalid device credentials")
	}
}
