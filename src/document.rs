pub use crate::internal::document_api::{
    AssociationType, DocAccessEditErr, DocumentAccessResult, DocumentDecryptResult,
    DocumentEncryptResult, DocumentListMeta, DocumentListResult, DocumentMetadataResult,
    UserOrGroup, VisibleGroup, VisibleUser,
};
use crate::internal::validate_simple_policy_field_id;
use crate::{
    internal::{
        document_api::{self, DocumentId, DocumentName},
        group_api::GroupId,
        user_api::UserId,
    },
    IronOxideErr, Result,
};
use itertools::{Either, EitherOrBoth, Itertools};
use std::convert::TryFrom;
use tokio::runtime::current_thread::Runtime;

/// Optional parameters that can be provided when encrypting a new document.
#[derive(Debug, PartialEq, Clone)]
pub struct DocumentEncryptOpts {
    id: Option<DocumentId>,
    name: Option<DocumentName>,
    grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
}
#[derive(Debug, PartialEq, Clone)]
pub struct ExplicitGrant {
    grant_to_author: bool,
    grants: Vec<UserOrGroup>,
}

impl ExplicitGrant {
    pub fn new(grant_to_author: bool, grants: &[UserOrGroup]) -> ExplicitGrant {
        ExplicitGrant {
            grant_to_author,
            grants: grants.to_vec(),
        }
    }
}

impl<'a> DocumentEncryptOpts {
    pub fn new(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grants: EitherOrBoth<ExplicitGrant, PolicyGrant>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts { grants, name, id }
    }
    pub fn with_explicit_grants(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        grant_to_author: bool,
        grants: Vec<UserOrGroup>,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts {
            id,
            name,
            grants: EitherOrBoth::Left(ExplicitGrant {
                grants,
                grant_to_author,
            }),
        }
    }

    pub fn with_policy_grants(
        id: Option<DocumentId>,
        name: Option<DocumentName>,
        policy: PolicyGrant,
    ) -> DocumentEncryptOpts {
        DocumentEncryptOpts {
            id,
            name,
            grants: EitherOrBoth::Right(policy),
        }
    }
}

/// Document access granted by a policy.
///
/// Policies are defined using the ironcore admin console: https://admin.ironcorelabs.com/policy
/// In the future policies will be able to be programmatically defined using ironoxide.
///
/// A policy could look something like:
/// ```json
/// {
///  "dataSubjects": [
///    "PATIENT",
///    "EMPLOYEE"
///  ],
///  "sensitivities": [
///    "RESTRICTED",
///    "CLASSIFIED",
///    "INTERNAL"
///  ],
///  "categories": [
///    "HEALTH",
///    "PII"
///  ],
///  "rules": [
///    {
///      "sensitivity": "RESTRICTED",
///      "users": [
///        "%USER%"
///      ],
///      "dataSubject": "PATIENT",
///      "groups": [
///        "group_other_%USER%",
///        "group_id_doctors",
///        "data_recovery"
///      ],
///      "category": "HEALTH"
///    },
///    {
///      "sensitivity": "INTERNAL",
///      "users": [
///        "joe@ironcorelabs",
///        "%LOGGED_IN_USER%"
///      ],
///      "groups": [
///        "group_%LOGGED_IN_USER%",
///        "data_recovery"
///      ],
///      "category": "PII"
///    },
///    {
///      "groups": [
///        "data_recovery"
///      ],
///    },
///  ]
/// }
/// ```
///
/// A policy is stored on the server and yields a list of users and groups when applied.
/// The triple (`category`, `sensitivity`, `data_subject`) maps to a single policy rule. Each policy
/// rule may generate any number of users/groups.
///
/// How a `substitute_user_id` is a `UserId` that will be used to replace the `%USER%` placeholder.
/// `%LOGGED_IN_USER%` is a special token that will be replaced by the user currently authenticated
/// to make SDK calls.
///
/// Rules in the policy are matched from top to bottom. If more than one rule would match a `PolicyGrant`
/// the first one will be applied.
///
/// Example:
/// If the current user of the sdk is "alice@ironcorelabs" and the following PolicyGrant is evaluated,
/// `PolicyGrant::new("PII".try_from()?, "INTERNAL".try_from()?, None, None)` will match the last rule
/// in the example policy, above and will return users: [joe@ironcorelabs, alice@ironcorelabs] and
/// groups [group_alice@ironcorelabs, data_recovery"]
///
#[derive(Debug, PartialEq, Clone)]
pub struct PolicyGrant {
    category: Option<Category>,
    sensitivity: Option<Sensitivity>,
    data_subject: Option<DataSubject>,
    substitute_user_id: Option<SubstituteId>,
}

impl PolicyGrant {
    pub fn new(
        category: Option<Category>,
        sensitivity: Option<Sensitivity>,
        data_subject: Option<DataSubject>,
        substitute_user: Option<UserId>,
    ) -> PolicyGrant {
        PolicyGrant {
            category,
            sensitivity,
            data_subject,
            substitute_user_id: substitute_user.map(|u| u.into()),
        }
    }

    pub fn category(&self) -> Option<&Category> {
        self.category.as_ref()
    }

    pub fn sensitivity(&self) -> Option<&Sensitivity> {
        self.sensitivity.as_ref()
    }

    pub fn data_subject(&self) -> Option<&DataSubject> {
        self.data_subject.as_ref()
    }
    pub fn substitute_id(&self) -> Option<&SubstituteId> {
        self.substitute_user_id.as_ref()
    }
}

impl Default for PolicyGrant {
    fn default() -> Self {
        PolicyGrant {
            category: None,
            sensitivity: None,
            data_subject: None,
            substitute_user_id: None,
        }
    }
}
macro_rules! policy_field {
    ($t: ident, $l: literal) => {
        #[derive(Debug, PartialEq, Clone)]
        pub struct $t(pub(crate) String);

        impl TryFrom<&str> for $t {
            type Error = IronOxideErr;

            fn try_from(value: &str) -> Result<Self> {
                validate_simple_policy_field_id(value, $l).map(|v| Self(v))
            }
        }

        impl $t {
            pub(crate) const QUERY_PARAM: &'static str = $l;
        }
    };
}

policy_field!(Category, "category");
policy_field!(DataSubject, "dataSubject");
policy_field!(Sensitivity, "sensitivity");

#[derive(Debug, PartialEq, Clone)]
pub struct SubstituteId(pub(crate) UserId);

impl From<UserId> for SubstituteId {
    fn from(u: UserId) -> Self {
        SubstituteId(u)
    }
}

impl SubstituteId {
    pub(crate) const QUERY_PARAM: &'static str = "id";
}
impl Default for DocumentEncryptOpts {
    fn default() -> Self {
        DocumentEncryptOpts::with_explicit_grants(None, None, true, vec![])
    }
}

pub trait DocumentOps {
    /// List all of the documents that the current user is able to decrypt.
    ///
    /// # Returns
    /// `DocumentListResult` struct with vec of metadata about each document the user can decrypt.
    fn document_list(&self) -> Result<DocumentListResult>;

    /// Get the metadata for a specific document given its ID.
    ///
    /// # Arguments
    /// - `id` - Unique ID of the document to retrieve
    ///
    /// # Returns
    /// `DocumentMetadataResult` with details about the requested document.
    fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult>;

    /// Attempt to parse the document ID out of an encrypted document.
    ///
    /// # Arguments
    /// - `encrypted_document` - Encrypted document bytes
    ///
    /// # Returns
    /// `Result<DocumentId>` Fails if provided encrypted document has no header, otherwise returns extracted ID.
    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId>;

    /// Encrypt the provided document bytes.
    ///
    /// # Arguments
    /// - `document_data` - Bytes of the document to encrypt
    /// - `encrypt_opts` - Optional document encrypt parameters. Includes
    ///       `id` - Unique ID to use for the document. Document ID will be stored unencrypted and must be unique per segment.
    ///       `name` - Non-unique name to use in the document. Document name will **not** be encrypted.
    ///       `grant_to_author` - Flag determining whether to encrypt to the calling user or not. If set to false at least one value must be present in the `grant` list.
    ///       `grants` - List of users/groups to grant access to this document once encrypted
    fn document_encrypt(
        &mut self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult>;

    /// Update the encrypted content of an existing document. Persists any existing access to other users and groups.
    ///
    /// # Arguments
    /// - `id` - ID of document to update.
    /// - `new_document_data` - Updated document content to encrypt.
    fn document_update_bytes(
        &mut self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult>;

    /// Decrypts the provided encrypted document and returns details about the document as well as its decrypted bytes.
    ///
    /// # Arguments
    /// - `encrypted_document` - Bytes of encrypted document. Should be the same bytes returned from `document_encrypt`.
    ///
    /// # Returns
    /// `Result<DocumentDecryptResult>` Includes metadata about the provided document as well as the decrypted document bytes.
    fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult>;

    /// Update a document name to a new value or clear its value.
    ///
    /// # Arguments
    /// - `id` - ID of the document to update
    /// - `name` - New name for the document. Provide a Some to update to a new name and a None to clear the name field.
    ///
    /// # Returns
    /// `Result<DocumentMetadataResult>` Metadata about the document that was updated.
    fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult>;

    /// Grant access to a document. Recipients of document access can be either users or groups.
    ///
    /// # Arguments
    /// `document_id` - id of the document whose access is is being modified
    /// `grant_list` - list of grants. Elements represent either a user or a group.
    ///
    /// # Returns
    /// Outer result indicates that the request failed either on the client or that the server rejected
    /// the whole request. If the outer result is `Ok` then each individual grant to a user/group
    /// either succeeded or failed.
    fn document_grant_access(
        &mut self,
        document_id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult>;

    /// Revoke access from a document. Revocation of document access can be either users or groups.
    ///
    /// # Arguments
    /// `document_id` - id of the document whose access is is being modified
    /// `revoke_list` - List of revokes. Elements represent either a user or a group.
    ///
    /// # Returns
    /// Outer result indicates that the request failed either on the client or that the server rejected
    /// the whole request. If the outer result is `Ok` then each individual revoke from a user/group
    /// either succeeded or failed.
    fn document_revoke_access(
        &self,
        document_id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult>;
}

impl DocumentOps for crate::IronOxide {
    fn document_list(&self) -> Result<DocumentListResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(document_api::document_list(self.device.auth()))
    }

    fn document_get_metadata(&self, id: &DocumentId) -> Result<DocumentMetadataResult> {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(document_api::document_get_metadata(self.device.auth(), id))
    }

    fn document_get_id_from_bytes(&self, encrypted_document: &[u8]) -> Result<DocumentId> {
        document_api::get_id_from_bytes(encrypted_document)
    }

    fn document_encrypt(
        &mut self,
        document_data: &[u8],
        encrypt_opts: &DocumentEncryptOpts,
    ) -> Result<DocumentEncryptResult> {
        let mut rt = Runtime::new().unwrap();
        let encrypt_opts = encrypt_opts.clone();

        let (explicit_users, explicit_groups, grant_to_author, policy_grants) =
            match encrypt_opts.grants {
                EitherOrBoth::Left(explicit_grants) => {
                    let (users, groups) = partition_user_or_group(&explicit_grants.grants);
                    (users, groups, explicit_grants.grant_to_author, None)
                }
                EitherOrBoth::Right(policy_grant) => (vec![], vec![], false, Some(policy_grant)),
                EitherOrBoth::Both(explicit_grants, policy_grant) => {
                    let (users, groups) = partition_user_or_group(&explicit_grants.grants);
                    (
                        users,
                        groups,
                        explicit_grants.grant_to_author,
                        Some(policy_grant),
                    )
                }
            };

        rt.block_on(document_api::encrypt_document(
            self.device.auth(),
            &mut self.recrypt,
            &self.user_master_pub_key,
            &mut self.rng,
            document_data,
            encrypt_opts.id,
            encrypt_opts.name,
            grant_to_author,
            &explicit_users,
            &explicit_groups,
            policy_grants.as_ref(),
        ))
    }

    fn document_update_bytes(
        &mut self,
        id: &DocumentId,
        new_document_data: &[u8],
    ) -> Result<DocumentEncryptResult> {
        let mut rt = Runtime::new().unwrap();

        rt.block_on(document_api::document_update_bytes(
            self.device.auth(),
            &mut self.recrypt,
            self.device.private_device_key(),
            &mut self.rng,
            id,
            &new_document_data,
        ))
    }

    fn document_decrypt(&self, encrypted_document: &[u8]) -> Result<DocumentDecryptResult> {
        let mut rt = Runtime::new().unwrap();

        rt.block_on(document_api::decrypt_document(
            self.device.auth(),
            &self.recrypt,
            self.device.private_device_key(),
            encrypted_document,
        ))
    }

    fn document_update_name(
        &self,
        id: &DocumentId,
        name: Option<&DocumentName>,
    ) -> Result<DocumentMetadataResult> {
        let mut rt = Runtime::new().unwrap();

        rt.block_on(document_api::update_document_name(
            self.device.auth(),
            id,
            name,
        ))
    }

    fn document_grant_access(
        &mut self,
        id: &DocumentId,
        grant_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        let mut rt = Runtime::new().unwrap();

        let (users, groups) = partition_user_or_group(grant_list);

        rt.block_on(document_api::document_grant_access(
            self.device.auth(),
            &mut self.recrypt,
            id,
            &self.user_master_pub_key,
            &self.device.private_device_key(),
            &users,
            &groups,
        ))
    }

    fn document_revoke_access(
        &self,
        id: &DocumentId,
        revoke_list: &Vec<UserOrGroup>,
    ) -> Result<DocumentAccessResult> {
        let mut rt = Runtime::new().unwrap();

        rt.block_on(document_api::document_revoke_access(
            self.device.auth(),
            id,
            revoke_list,
        ))
    }
}

fn partition_user_or_group(uog_slice: &[UserOrGroup]) -> (Vec<UserId>, Vec<GroupId>) {
    uog_slice
        .into_iter()
        .partition_map(|access_grant| match access_grant {
            UserOrGroup::User { id } => Either::Left(id.clone()),
            UserOrGroup::Group { id } => Either::Right(id.clone()),
        })
}
