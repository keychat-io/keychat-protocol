use std::collections::HashMap;

use kc::group_context_extension::NostrGroupDataExtension;
use kc::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
use kc::user::{Group, MlsUser, CIPHERSUITE};
use openmls::group::{MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig};
use openmls::key_packages::KeyPackage;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::{
    BasicCredential, Capabilities, Extension, ExtensionType, Extensions, KeyPackageIn,
    MlsMessageIn, ProcessedMessageContent, Proposal, ProposalType, ProtocolVersion,
    RequiredCapabilitiesExtension, StagedWelcome, UnknownExtension,
};
use openmls_traits::OpenMlsProvider;
use rand::RngCore;

use crate::error::{KeychatError, Result};

use super::types::{
    AddMembersResult, CommitResult, CommitTypeResult, DecryptedGroupMessage, GroupMessage,
    KeyPackageResult, ProcessedMlsMessage, RemoveMemberResult,
};

const UNKNOWN_EXTENSION_TYPE: u16 = 0xF233;

pub(crate) struct ManagedUser {
    pub(crate) mls_user: MlsUser,
}

impl ManagedUser {
    pub(crate) async fn load(
        provider: OpenMlsRustPersistentCrypto,
        nostr_id: String,
    ) -> Result<Self> {
        let mls_user = MlsUser::load(provider, nostr_id).await.map_err(mls_err)?;
        Ok(Self { mls_user })
    }

    pub(crate) async fn update(&mut self, nostr_id: String, is_identity: bool) -> Result<()> {
        self.mls_user
            .update(nostr_id, is_identity)
            .await
            .map_err(mls_err)
    }

    pub(crate) fn create_key_package(&mut self) -> Result<KeyPackageResult> {
        let mut identity = self.mls_user.identity.write().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity write lock".to_owned())
        })?;
        let capabilities: Capabilities = identity.create_capabilities().map_err(mls_err)?;
        let ciphersuite = identity.ciphersuite_value().to_string();
        let extensions = identity.extensions_value();
        let key_package =
            identity.add_key_package(CIPHERSUITE, &self.mls_user.provider, capabilities);
        let key_package_serialized = key_package.tls_serialize_detached().map_err(mls_err)?;

        Ok(KeyPackageResult {
            key_package: hex::encode(key_package_serialized),
            mls_protocol_version: "1.0".to_owned(),
            ciphersuite,
            extensions,
        })
    }

    pub(crate) fn parse_key_package(&self, key_package_hex: &str) -> Result<KeyPackage> {
        let key_package_bytes = hex::decode(key_package_hex)?;
        let key_package_in =
            KeyPackageIn::tls_deserialize(&mut key_package_bytes.as_slice()).map_err(mls_err)?;

        key_package_in
            .validate(self.mls_user.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls_err)
    }

    pub(crate) fn create_group(&mut self, group_id: String, group_name: &str) -> Result<String> {
        let identity = self.mls_user.identity.read().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity read lock".to_owned())
        })?;

        let group_data = NostrGroupDataExtension::new(
            group_name.to_owned(),
            String::new(),
            vec![self.identity_string()?],
            Vec::new(),
            "active".to_owned(),
        );
        let serialized_group_data = group_data.tls_serialize_detached().map_err(mls_err)?;

        let required_extension_types = &[ExtensionType::Unknown(UNKNOWN_EXTENSION_TYPE)];
        let required_capabilities = Extension::RequiredCapabilities(
            RequiredCapabilitiesExtension::new(required_extension_types, &[], &[]),
        );
        let extensions = vec![
            Extension::Unknown(
                UNKNOWN_EXTENSION_TYPE,
                UnknownExtension(serialized_group_data),
            ),
            required_capabilities,
        ];

        let capabilities: Capabilities = identity.create_capabilities().map_err(mls_err)?;
        let group_create_config = MlsGroupCreateConfig::builder()
            .capabilities(capabilities)
            .use_ratchet_tree_extension(true)
            .with_group_context_extensions(Extensions::from_vec(extensions).map_err(mls_err)?)
            .map_err(mls_err)?
            .build();

        let mls_group = MlsGroup::new_with_group_id(
            &self.mls_user.provider,
            &identity.signer,
            &group_create_config,
            openmls::group::GroupId::from_slice(group_id.as_bytes()),
            identity.credential_with_key.clone(),
        )
        .map_err(mls_err)?;
        drop(identity);

        let mut groups = self.groups_write()?;
        if groups.contains_key(&group_id) {
            return Err(KeychatError::Mls(format!(
                "group '{group_id}' already exists"
            )));
        }
        groups.insert(group_id.clone(), Group { mls_group });
        drop(groups);
        self.mls_user.group_list.insert(group_id.clone());

        Ok(group_id)
    }

    pub(crate) fn add_member(
        &mut self,
        group_id: &str,
        key_package_hex: &str,
    ) -> Result<AddMembersResult> {
        let key_package = self.parse_key_package(key_package_hex)?;
        let identity = self.mls_user.identity.read().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity read lock".to_owned())
        })?;
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        let (commit, welcome, _) = group
            .mls_group
            .add_members(&self.mls_user.provider, &identity.signer, &[key_package])
            .map_err(mls_err)?;
        let commit_message = commit.to_bytes().map_err(mls_err)?;
        let welcome = welcome.to_bytes().map_err(mls_err)?;
        group
            .mls_group
            .merge_pending_commit(&self.mls_user.provider)
            .map_err(mls_err)?;

        Ok(AddMembersResult {
            commit_message,
            welcome,
        })
    }

    pub(crate) fn remove_member(
        &mut self,
        group_id: &str,
        member_nostr_id: &str,
    ) -> Result<RemoveMemberResult> {
        let identity = self.mls_user.identity.read().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity read lock".to_owned())
        })?;
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;

        let mut leaf_index = None;
        for member in group.mls_group.members() {
            let identity = credential_to_string(&member.credential)?;
            if identity == member_nostr_id {
                leaf_index = Some(member.index);
                break;
            }
        }
        let leaf_index = leaf_index.ok_or_else(|| {
            KeychatError::Mls(format!(
                "member '{member_nostr_id}' not found in group '{group_id}'"
            ))
        })?;

        let (commit, _, _) = group
            .mls_group
            .remove_members(&self.mls_user.provider, &identity.signer, &[leaf_index])
            .map_err(mls_err)?;
        let commit_message = commit.to_bytes().map_err(mls_err)?;
        group
            .mls_group
            .merge_pending_commit(&self.mls_user.provider)
            .map_err(mls_err)?;

        Ok(RemoveMemberResult { commit_message })
    }

    pub(crate) fn join_group_from_welcome(&mut self, welcome_bytes: &[u8]) -> Result<String> {
        let (staged_welcome, group_id) = self.parse_welcome_message(welcome_bytes)?;
        let mls_group = staged_welcome
            .into_group(&self.mls_user.provider)
            .map_err(mls_err)?;

        let mut groups = self.groups_write()?;
        if groups.contains_key(&group_id) {
            return Err(KeychatError::Mls(format!(
                "group '{group_id}' already exists"
            )));
        }
        groups.insert(group_id.clone(), Group { mls_group });
        drop(groups);
        self.mls_user.group_list.insert(group_id.clone());

        Ok(group_id)
    }

    pub(crate) fn encrypt_group_message(
        &mut self,
        group_id: &str,
        message: &str,
    ) -> Result<GroupMessage> {
        let identity = self.mls_user.identity.read().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity read lock".to_owned())
        })?;
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        let message_out = group
            .mls_group
            .create_message(
                &self.mls_user.provider,
                &identity.signer,
                message.as_bytes(),
            )
            .map_err(mls_err)?;
        let ciphertext = message_out.0.to_bytes().map_err(mls_err)?;
        let listen_key = listen_key_for_group(&self.mls_user.provider, &group.mls_group)?;

        Ok(GroupMessage {
            ciphertext,
            listen_key,
        })
    }

    pub(crate) fn decrypt_group_message(
        &mut self,
        group_id: &str,
        ciphertext: &[u8],
    ) -> Result<DecryptedGroupMessage> {
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        let msg = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(mls_err)?;
        let processed = group
            .mls_group
            .process_message(
                &self.mls_user.provider,
                msg.into_protocol_message().ok_or_else(|| {
                    KeychatError::Mls("unexpected non-protocol MLS message".to_owned())
                })?,
            )
            .map_err(mls_err)?;

        let sender_nostr_id = credential_to_string(processed.0.credential())?;
        let listen_key = listen_key_for_group(&self.mls_user.provider, &group.mls_group)?;
        match processed.0.into_content() {
            ProcessedMessageContent::ApplicationMessage(application_message) => {
                let plaintext = String::from_utf8(application_message.into_bytes())?;
                Ok(DecryptedGroupMessage {
                    plaintext,
                    sender_nostr_id,
                    listen_key,
                })
            }
            _ => Err(KeychatError::Mls(
                "expected application message, got commit/proposal; use process_mls_message() instead".to_owned(),
            )),
        }
    }

    pub(crate) fn process_commit(
        &mut self,
        group_id: &str,
        commit_bytes: &[u8],
    ) -> Result<CommitResult> {
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        let commit = MlsMessageIn::tls_deserialize_exact(commit_bytes).map_err(mls_err)?;
        let processed = group
            .mls_group
            .process_message(
                &self.mls_user.provider,
                commit.into_protocol_message().ok_or_else(|| {
                    KeychatError::Mls("unexpected non-protocol MLS message".to_owned())
                })?,
            )
            .map_err(mls_err)?;
        let sender = credential_to_string(processed.0.credential())?;

        match processed.0.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let proposals: Vec<_> = staged_commit.queued_proposals().collect();
                let mut commit_type = CommitTypeResult::Update;
                let mut operated_members = Vec::new();

                if let Some(first) = proposals.first() {
                    match first.proposal().proposal_type() {
                        ProposalType::Add => {
                            commit_type = CommitTypeResult::Add;
                            for proposal in proposals {
                                if let Proposal::Add(add) = proposal.proposal() {
                                    operated_members.push(credential_to_string(
                                        add.key_package().leaf_node().credential(),
                                    )?);
                                }
                            }
                        }
                        ProposalType::Remove => {
                            commit_type = CommitTypeResult::Remove;
                        }
                        ProposalType::GroupContextExtensions => {
                            commit_type = CommitTypeResult::GroupContextExtensions;
                        }
                        _ => {}
                    }
                }

                group
                    .mls_group
                    .merge_staged_commit(&self.mls_user.provider, *staged_commit)
                    .map_err(mls_err)?;

                Ok(CommitResult {
                    sender,
                    commit_type,
                    operated_members: Some(operated_members),
                })
            }
            _ => Err(KeychatError::Mls(
                "expected MLS staged commit while processing commit".to_owned(),
            )),
        }
    }

    /// Get the export_secret derived Nostr keypair for NIP-44 encrypt/decrypt.
    /// Keychat app wraps MLS ciphertext in NIP-44 using this keypair.
    pub(crate) fn get_export_secret_keypair(
        &mut self,
        group_id: &str,
    ) -> Result<crate::identity::NostrKeypair> {
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        export_secret_keypair(&self.mls_user.provider, &group.mls_group)
    }

    pub(crate) fn get_group_listen_key(&mut self, group_id: &str) -> Result<String> {
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        listen_key_for_group(&self.mls_user.provider, &group.mls_group)
    }

    pub(crate) fn leave_group(&mut self, group_id: &str) -> Result<Vec<u8>> {
        let identity = self.mls_user.identity.read().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity read lock".to_owned())
        })?;
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        let leave = group
            .mls_group
            .leave_group(&self.mls_user.provider, &identity.signer)
            .map_err(mls_err)?;
        let leave_bytes = leave.to_bytes().map_err(mls_err)?;

        groups.remove(group_id);
        drop(groups);
        self.mls_user.group_list.remove(group_id);
        Ok(leave_bytes)
    }

    pub(crate) fn list_groups(&self) -> Vec<String> {
        let mut groups: Vec<String> = self.mls_user.group_list.iter().cloned().collect();
        groups.sort();
        groups
    }

    pub(crate) fn identity_string(&self) -> Result<String> {
        let identity = self.mls_user.identity.read().map_err(|_| {
            KeychatError::Mls("failed to acquire MLS identity read lock".to_owned())
        })?;
        let identity = String::from_utf8(
            identity
                .credential_with_key
                .credential
                .serialized_content()
                .to_vec(),
        )?;
        Ok(identity)
    }

    fn parse_welcome_message(&mut self, welcome_bytes: &[u8]) -> Result<(StagedWelcome, String)> {
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let welcome = MlsMessageIn::tls_deserialize_exact(welcome_bytes).map_err(mls_err)?;
        let welcome = welcome
            .into_welcome()
            .ok_or_else(|| KeychatError::Mls("expected MLS welcome message".to_owned()))?;

        let staged_welcome =
            StagedWelcome::new_from_welcome(&self.mls_user.provider, &join_config, welcome, None)
                .map_err(mls_err)?;
        let group_id = String::from_utf8(
            staged_welcome
                .group_context()
                .group_id()
                .as_slice()
                .to_vec(),
        )?;

        Ok((staged_welcome, group_id))
    }

    /// Process any inbound MLS message (application or commit).
    /// Returns a unified `ProcessedMlsMessage` enum.
    /// Preferred over separate `decrypt_group_message` / `process_commit`,
    /// since `process_message` consumes epoch state on the first call.
    pub(crate) fn process_mls_message(
        &mut self,
        group_id: &str,
        message_bytes: &[u8],
    ) -> Result<ProcessedMlsMessage> {
        let mut groups = self.groups_write()?;
        let group = group_mut(&mut groups, group_id)?;
        let msg = MlsMessageIn::tls_deserialize_exact(message_bytes).map_err(mls_err)?;
        let processed = group
            .mls_group
            .process_message(
                &self.mls_user.provider,
                msg.into_protocol_message().ok_or_else(|| {
                    KeychatError::Mls("unexpected non-protocol MLS message".to_owned())
                })?,
            )
            .map_err(mls_err)?;

        let sender = credential_to_string(processed.0.credential())?;

        match processed.0.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                let listen_key = listen_key_for_group(&self.mls_user.provider, &group.mls_group)?;
                let plaintext = String::from_utf8(app_msg.into_bytes())?;
                Ok(ProcessedMlsMessage::Application {
                    plaintext,
                    sender_nostr_id: sender,
                    listen_key,
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let proposals: Vec<_> = staged_commit.queued_proposals().collect();
                let mut commit_type = CommitTypeResult::Update;
                let mut operated_members = Vec::new();

                if let Some(first) = proposals.first() {
                    match first.proposal().proposal_type() {
                        ProposalType::Add => {
                            commit_type = CommitTypeResult::Add;
                            for proposal in &proposals {
                                if let Proposal::Add(add) = proposal.proposal() {
                                    operated_members.push(credential_to_string(
                                        add.key_package().leaf_node().credential(),
                                    )?);
                                }
                            }
                        }
                        ProposalType::Remove => commit_type = CommitTypeResult::Remove,
                        ProposalType::GroupContextExtensions => {
                            commit_type = CommitTypeResult::GroupContextExtensions;
                        }
                        _ => {}
                    }
                }

                group
                    .mls_group
                    .merge_staged_commit(&self.mls_user.provider, *staged_commit)
                    .map_err(mls_err)?;
                let listen_key = listen_key_for_group(&self.mls_user.provider, &group.mls_group)?;

                Ok(ProcessedMlsMessage::Commit {
                    sender,
                    commit_type,
                    operated_members: Some(operated_members),
                    listen_key,
                })
            }
            _ => Err(KeychatError::Mls(
                "unexpected MLS message type (not application or commit)".to_owned(),
            )),
        }
    }

    fn groups_write(&self) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<String, Group>>> {
        self.mls_user
            .groups
            .write()
            .map_err(|_| KeychatError::Mls("failed to acquire MLS groups write lock".to_owned()))
    }
}

fn group_mut<'a>(groups: &'a mut HashMap<String, Group>, group_id: &str) -> Result<&'a mut Group> {
    groups
        .get_mut(group_id)
        .ok_or_else(|| KeychatError::Mls(format!("no group with id {group_id}")))
}

fn credential_to_string(credential: &openmls::credentials::Credential) -> Result<String> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(mls_err)?;
    String::from_utf8(basic.identity().to_vec()).map_err(Into::into)
}

fn export_secret_keypair(
    provider: &OpenMlsRustPersistentCrypto,
    group: &MlsGroup,
) -> Result<crate::identity::NostrKeypair> {
    let export_secret = group
        .export_secret(provider, "nostr", b"nostr", 32)
        .map_err(mls_err)?;
    let key_hex = hex::encode(export_secret);
    let keys = nostr::Keys::parse(&key_hex).map_err(|err| KeychatError::Mls(err.to_string()))?;
    let secret_bytes = keys.secret_key().secret_bytes();
    let public_hex = hex::encode(
        keys.public_key()
            .xonly()
            .map_err(|err| KeychatError::Mls(err.to_string()))?
            .serialize(),
    );
    crate::identity::NostrKeypair::from_secret_key_bytes(&secret_bytes, &public_hex)
}

fn listen_key_for_group(
    provider: &OpenMlsRustPersistentCrypto,
    group: &MlsGroup,
) -> Result<String> {
    let kp = export_secret_keypair(provider, group)?;
    Ok(kp.public_key_hex())
}

pub(crate) fn mls_err<E: std::fmt::Display>(err: E) -> KeychatError {
    KeychatError::Mls(err.to_string())
}

pub(crate) fn random_group_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
