#[macro_export]
macro_rules! document_advanced_ops {
    ($meta_macro:meta) => {
        #[$meta_macro]
        pub trait DocumentAdvancedOps {
            /// (Advanced) Encrypt the provided document bytes. Return the encrypted document encryption keys (EDEKs)
            /// instead of creating a document entry in the IronCore webservice.
            ///
            /// The webservice is still needed for looking up public keys and evaluating policies, but no
            /// document is created and the edeks are not stored. An additional burden is put on the caller
            /// in that the encrypted data AND the edeks need to be provided for decryption.
            ///
            /// # Arguments
            /// - `document_data` - Bytes of the document to encrypt
            /// - `encrypt_opts` - Optional document encrypt parameters. Includes
            ///       `id` - Unique ID to use for the document. Document ID will be stored unencrypted and must be unique per segment.
            ///       `name` - (Ignored) - Any name provided will be ignored
            ///       `grant_to_author` - Flag determining whether to encrypt to the calling user or not. If set to false at least one value must be present in the `grants` list.
            ///       `grants` - List of users/groups to grant access to this document once encrypted
            //#[add_async($macro1)]
            fn document_encrypt_unmanaged(
                &self,
                data: &[u8],
                encrypt_opts: &DocumentEncryptOpts,
            ) -> Result<DocumentEncryptUnmanagedResult>;

            /// (Advanced) Decrypt a document not managed by the ironcore service. Both the encrypted
            /// data and the encrypted deks need to be provided.
            ///
            /// The webservice is still needed to transform a chosen encrypted dek so it can be decrypted
            /// by the caller's private key.
            ///
            /// # Arguments
            /// - `encrypted_data` - Encrypted document
            /// - `encrypted_deks` - Associated encrypted DEKs for the `encrypted_data`
            fn document_decrypt_unmanaged(
                &self,
                encrypted_data: &[u8],
                encrypted_deks: &[u8],
            ) -> Result<DocumentDecryptUnmanagedResult>;
        }
    };
}

#[macro_export]
macro_rules! document_ops {
    ($meta_macro:meta) => {
        #[$meta_macro]
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
                &self,
                document_data: &[u8],
                encrypt_opts: &DocumentEncryptOpts,
            ) -> Result<DocumentEncryptResult>;

            /// Update the encrypted content of an existing document. Persists any existing access to other users and groups.
            ///
            /// # Arguments
            /// - `id` - ID of document to update.
            /// - `new_document_data` - Updated document content to encrypt.
            fn document_update_bytes(
                &self,
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
                &self,
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
    };
}

#[macro_export]
macro_rules! group_ops {
    ($meta_macro:meta) => {
        #[$meta_macro]
        pub trait GroupOps {
            /// List all of the groups that the current user is either an admin or member of.
            ///
            /// # Returns
            /// `GroupListResult` List of (abbreviated) metadata about each group the user is a part of.
            fn group_list(&self) -> Result<GroupListResult>;

            /// Create a group. The creating user will become a group admin and by default a group member.
            ///
            /// # Arguments
            /// `group_create_opts` - See `GroupCreateOpts`. Use the `Default` implementation for defaults.
            fn group_create(
                &self,
                group_create_opts: &GroupCreateOpts,
            ) -> Result<GroupCreateResult>;

            /// Get the full metadata for a specific group given its ID.
            ///
            /// # Arguments
            /// - `id` - Unique ID of the group to retrieve
            ///
            /// # Returns
            /// `GroupMetaResult` with details about the requested group.
            fn group_get_metadata(&self, id: &GroupId) -> Result<GroupGetResult>;

            /// Delete the identified group. Group does not have to be empty of admins/members in order to
            /// delete the group. **Warning: Deletion of a group will cause all documents encrypted to that
            /// group to no longer be decryptable. Caution should be used when deleting groups.**
            ///
            /// # Arguments
            /// `id` - Unique id of group
            ///
            /// # Returns
            /// Deleted group id or error
            fn group_delete(&self, id: &GroupId) -> Result<GroupId>;

            /// Update a group name to a new value or clear its value.
            ///
            /// # Arguments
            /// - `id` - ID of the group to update
            /// - `name` - New name for the group. Provide a Some to update to a new name and a None to clear the name field.
            ///
            /// # Returns
            /// `Result<GroupMetaResult>` Metadata about the group that was updated.
            fn group_update_name(
                &self,
                id: &GroupId,
                name: Option<&GroupName>,
            ) -> Result<GroupMetaResult>;

            /// Add the users as members of a group.
            ///
            /// # Arguments
            /// - `id` - ID of the group to add members to
            /// - `users` - The list of users thet will be added to the group as members.
            /// # Returns
            /// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
            ///   the reason they were not.
            fn group_add_members(
                &self,
                id: &GroupId,
                users: &[UserId],
            ) -> Result<GroupAccessEditResult>;

            /// Remove a list of users as members from the group.
            ///
            /// # Arguments
            /// - `id` - ID of the group to remove members from
            /// - `revoke_list` - List of user IDs to remove as members
            ///
            /// # Returns
            /// `Result<GroupAccessEditResult>` List of users that were removed. Also contains the users that failed to be removed
            ///    and the reason they were not.
            fn group_remove_members(
                &self,
                id: &GroupId,
                revoke_list: &[UserId],
            ) -> Result<GroupAccessEditResult>;

            /// Add the users as admins of a group.
            ///
            /// # Arguments
            /// - `id` - ID of the group to add admins to
            /// - `users` - The list of users that will be added to the group as admins.
            /// # Returns
            /// GroupAccessEditResult, which contains all the users that were added. It also contains the users that were not added and
            ///   the reason they were not.
            fn group_add_admins(
                &self,
                id: &GroupId,
                users: &[UserId],
            ) -> Result<GroupAccessEditResult>;

            /// Remove a list of users as admins from the group.
            ///
            /// # Arguments
            /// - `id` - ID of the group
            /// - `revoke_list` - List of user IDs to remove as admins
            ///
            /// # Returns
            /// `Result<GroupAccessEditResult>` List of users that were removed. Also contains the users that failed to be removed
            ///    and the reason they were not.
            fn group_remove_admins(
                &self,
                id: &GroupId,
                revoke_list: &[UserId],
            ) -> Result<GroupAccessEditResult>;

            /// Rotate the provided group's private key, but leave the public key the same.
            /// There's no black magic here! This is accomplished via multi-party computation with the
            /// IronCore webservice.
            /// Note: You must be an admin of the group in order to rotate its private key.
            ///
            /// # Arguments
            /// `id` - ID of the group you wish to rotate the private key of
            ///
            /// # Returns
            /// An indication of whether the group's private key needs an additional rotation
            fn group_rotate_private_key(&self, id: &GroupId)
                -> Result<GroupUpdatePrivateKeyResult>;
        }
    };
}

#[macro_export]
macro_rules! user_ops {
    ($meta_macro:meta) => {
        #[$meta_macro]
        pub trait UserOps {
            /// Sync a new user within the IronCore system.
            ///
            /// # Arguments
            /// - `jwt` - Valid IronCore or Auth0 JWT
            /// - `password` - Password used to encrypt and escrow the user's private master key
            /// - `user_create_opts` - see [`UserCreateOpts`](struct.UserCreateOpts.html)
            /// # Returns
            /// Newly generated `UserCreateResult` or Err. For most use cases, this public key can
            /// be discarded as IronCore escrows your user's keys. The escrowed keys are unlocked
            /// by the provided password.
            fn user_create(
                jwt: &str,
                password: &str,
                user_create_opts: &UserCreateOpts,
            ) -> Result<UserCreateResult>;

            /// Get all the devices for the current user
            ///
            /// # Returns
            /// All devices for the current user, sorted by the device id.
            fn user_list_devices(&self) -> Result<UserDeviceListResult>;

            /// Generates a new device for the user specified in the signed JWT.
            ///
            /// This will result in a new transform key (from the user's master private key to the new device's public key)
            /// being generated and stored with the IronCore Service.
            ///
            /// # Arguments
            /// - `jwt`                   - Valid IronCore JWT
            /// - `password`              - Password used to encrypt and escrow the user's private key
            /// - `device_create_options` - Optional device create arguments, like device name
            ///
            /// # Returns
            /// Details about the newly created device.
            fn generate_new_device(
                jwt: &str,
                password: &str,
                device_create_options: &DeviceCreateOpts,
            ) -> Result<DeviceContext>;

            /// Delete a user device.
            ///
            /// If deleting the currently signed in device (None for `device_id`), the sdk will need to be
            /// reinitialized with `IronOxide.initialize()` before further use.
            ///
            /// # Arguments
            /// - `device_id` - ID of the device to delete. Get from `user_list_devices`. If None, deletes the currently SDK contexts device which
            ///                 once deleted will cause this SDK instance to no longer function.
            ///
            /// # Returns
            /// Id of deleted device or IronOxideErr
            fn user_delete_device(&self, device_id: Option<&DeviceId>) -> Result<DeviceId>;

            /// Verify a user given a JWT for their user record.
            ///
            /// # Arguments
            /// - `jwt` - Valid IronCore JWT
            ///
            /// # Returns
            /// Option of whether the user's account record exists in the IronCore system or not. Err if the request couldn't be made.
            fn user_verify(jwt: &str) -> Result<Option<UserResult>>;

            /// Get a list of user public keys given their IDs. Allows discovery of which user IDs have keys in the
            /// IronCore system to determine of they can be added to groups or have documents shared with them.
            ///
            /// # Arguments
            /// - users - List of user IDs to check
            ///
            /// # Returns
            /// Map from user ID to users public key. Only users who have public keys will be returned in the map.
            fn user_get_public_key(&self, users: &[UserId]) -> Result<HashMap<UserId, PublicKey>>;

            /// Rotate the current user's private key, but leave the public key the same.
            /// There's no black magic here! This is accomplished via multi-party computation with the
            /// IronCore webservice.
            ///
            /// # Arguments
            /// `password` - Password to unlock the current user's user master key
            ///
            /// # Returns
            /// The (encrypted) updated private key and associated metadata
            fn user_rotate_private_key(&self, password: &str)
                -> Result<UserUpdatePrivateKeyResult>;
        }
    };
}
