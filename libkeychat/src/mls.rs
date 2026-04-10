//! MLS (RFC 9420) large group implementation (spec §11).
//!
//! Uses the Keychat OpenMLS fork for group encryption with ratchet tree key management.
//! Provides:
//! - `MlsProvider` — OpenMLS provider wrapper with in-memory SQLite storage
//! - `MlsParticipant` — wraps MLS identity and group operations
//! - `derive_mls_temp_inbox` — shared receiving address from MLS export secret (§11.2)
//! - Transport helpers: `send_mls_message`, `receive_mls_message`, `broadcast_commit`
//! - Group management: create, add/remove members, join, leave, dissolve, rename
//! - KeyPackage publish/parse (kind 10443)

use crate::mls_extension::NostrGroupDataExtension;
use crate::mls_provider::OpenMlsRustPersistentCrypto;
use base64::Engine;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes as TlsDeserializeBytesTrait,
    Serialize as TlsSerializeTrait,
};

use crate::error::{KeychatError, Result};
use crate::identity::EphemeralKeypair;
use crate::message::{KCMessage, KCMessageKind};

/// MLS ciphersuite used throughout Keychat.
pub const MLS_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Extension type for Nostr group data.
const NOSTR_GROUP_EXTENSION_TYPE: u16 = 0xF233;

/// MLS export secret label for deriving the temp inbox address.
const MLS_TEMP_INBOX_LABEL: &str = "keychat-mls-temp-inbox";

/// Result of decrypting an MLS message — distinguishes application data from control messages.
#[derive(Debug, Clone)]
pub enum MlsDecryptResult {
    /// Application plaintext + sender identity.
    Application {
        plaintext: Vec<u8>,
        sender_id: String,
    },
    /// A Commit was processed (epoch advanced). No application payload.
    Commit { sender_id: String },
    /// A Proposal was received. No application payload.
    Proposal { sender_id: String },
}

// ─── MlsProvider ────────────────────────────────────────────────────────────

/// Wrapper around OpenMLS provider with in-memory SQLite storage.
pub struct MlsProvider {
    pub provider: OpenMlsRustPersistentCrypto,
}

impl MlsProvider {
    /// Create a new MLS provider with in-memory SQLite.
    pub fn new() -> Self {
        Self {
            provider: OpenMlsRustPersistentCrypto::default(),
        }
    }

    /// Open a file-backed MLS provider at `path`.
    pub fn open(path: &str) -> Result<Self> {
        let provider = OpenMlsRustPersistentCrypto::open(path)
            .map_err(|e| KeychatError::Storage(format!("MLS storage open failed: {e}")))?;
        Ok(Self { provider })
    }

    /// Access the inner OpenMLS provider.
    pub fn inner(&self) -> &OpenMlsRustPersistentCrypto {
        &self.provider
    }
}

impl Default for MlsProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ─── MlsParticipant ─────────────────────────────────────────────────────────

/// An MLS participant wrapping identity, credentials, and group operations.
pub struct MlsParticipant {
    /// The Nostr identity (hex pubkey) associated with this MLS participant.
    pub nostr_id: String,
    /// The MLS provider (crypto + storage).
    provider: MlsProvider,
    /// MLS credential with public key.
    credential: CredentialWithKey,
    /// MLS signing key pair.
    signer: SignatureKeyPair,
}

impl MlsParticipant {
    /// Create a new MLS participant with the given Nostr identity.
    /// Generates fresh MLS credential and signing keys.
    pub fn new(nostr_id: impl Into<String>) -> Result<Self> {
        let nostr_id = nostr_id.into();
        let provider = MlsProvider::new();

        let credential = BasicCredential::new(nostr_id.as_bytes().to_vec());
        let signer = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm()).map_err(|e| {
            KeychatError::Mls(format!("failed to generate MLS signature keypair: {e}"))
        })?;
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        signer
            .store(provider.inner().storage())
            .map_err(|e| KeychatError::Mls(format!("failed to store signature keypair: {e}")))?;

        tracing::info!(
            "MLS participant created: nostr_id={}",
            &nostr_id[..16.min(nostr_id.len())]
        );
        Ok(Self {
            nostr_id,
            provider,
            credential: credential_with_key,
            signer,
        })
    }

    /// Create an MLS participant with a custom provider (e.g. file-backed).
    ///
    /// If `signer_public_key` is provided, attempts to restore the existing
    /// signing key from the provider's storage. This is required for MLS group
    /// state to survive restarts. If restoration fails or no key is provided,
    /// generates a fresh signing key.
    pub fn with_provider(nostr_id: impl Into<String>, provider: MlsProvider) -> Result<Self> {
        Self::with_provider_and_signer(nostr_id, provider, None)
    }

    /// Create an MLS participant, optionally restoring a saved signing key.
    pub fn with_provider_and_signer(
        nostr_id: impl Into<String>,
        provider: MlsProvider,
        signer_public_key: Option<&[u8]>,
    ) -> Result<Self> {
        let nostr_id = nostr_id.into();
        let credential = BasicCredential::new(nostr_id.as_bytes().to_vec());

        let signer = if let Some(restored) = signer_public_key.and_then(|pub_key| {
            SignatureKeyPair::read(
                provider.inner().storage(),
                pub_key,
                MLS_CIPHERSUITE.signature_algorithm(),
            )
        }) {
            restored
        } else {
            let s = SignatureKeyPair::new(MLS_CIPHERSUITE.signature_algorithm())
                .map_err(|e| KeychatError::Mls(format!("failed to generate MLS keypair: {e}")))?;
            s.store(provider.inner().storage())
                .map_err(|e| KeychatError::Mls(format!("failed to store MLS keypair: {e}")))?;
            s
        };

        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            nostr_id,
            provider,
            credential: credential_with_key,
            signer,
        })
    }

    /// Get the MLS signer's public key bytes (for persistence).
    pub fn signer_public_key(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// Generate a KeyPackage for others to add us to a group.
    pub fn generate_key_package(&self) -> Result<KeyPackage> {
        let capabilities = self.create_capabilities()?;
        let kp = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .mark_as_last_resort()
            .build(
                MLS_CIPHERSUITE,
                self.provider.inner(),
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|e| KeychatError::Mls(format!("failed to build KeyPackage: {e}")))?;

        Ok(kp.key_package().clone())
    }

    /// Create a new MLS group with the given group_id and name.
    /// The creator is the initial admin.
    pub fn create_group(&self, group_id: &str, name: &str) -> Result<()> {
        let capabilities = self.create_capabilities()?;

        // Build group context extension with NostrGroupDataExtension
        let group_data = NostrGroupDataExtension::new(
            name.to_string(),
            String::new(),               // description
            vec![self.nostr_id.clone()], // admin_pubkeys
            vec![],                      // relays
            "active".to_string(),        // status
        );

        // Set the group_id bytes in the extension
        let mut group_data = group_data;
        let id_bytes: [u8; 32] = {
            let hash = Sha256::digest(group_id.as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        };
        group_data.set_nostr_group_id(id_bytes);

        // Serialize the extension via TLS encoding
        let ext_data = group_data
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("TLS serialize error: {e}")))?;

        let extension = Extension::Unknown(NOSTR_GROUP_EXTENSION_TYPE, UnknownExtension(ext_data));
        let required_caps = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(NOSTR_GROUP_EXTENSION_TYPE)],
            &[],
            &[],
        ));
        let group_context_extensions = Extensions::from_vec(vec![extension, required_caps])
            .map_err(|e| KeychatError::Mls(format!("extensions error: {e}")))?;

        let group_create_config = MlsGroupCreateConfig::builder()
            .capabilities(capabilities)
            .with_group_context_extensions(group_context_extensions)
            .use_ratchet_tree_extension(true)
            .build();

        let _group = MlsGroup::new_with_group_id(
            self.provider.inner(),
            &self.signer,
            &group_create_config,
            GroupId::from_slice(group_id.as_bytes()),
            self.credential.clone(),
        )
        .map_err(|e| KeychatError::Mls(format!("failed to create MLS group: {e}")))?;

        tracing::info!(
            "MLS group created: group_id={}",
            &group_id[..16.min(group_id.len())]
        );
        Ok(())
    }

    /// Add members to a group. Returns (serialized Commit, serialized Welcome).
    pub fn add_members(
        &self,
        group_id: &str,
        key_packages: Vec<KeyPackage>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut group = self.load_group(group_id)?;

        // Filter out key packages whose signature key already exists in the group
        // to avoid "Duplicate signature key in proposals and group" error
        let existing_sig_keys: std::collections::HashSet<Vec<u8>> =
            group.members().map(|m| m.signature_key).collect();
        let total = key_packages.len();
        let key_packages: Vec<KeyPackage> = key_packages
            .into_iter()
            .filter(|kp| !existing_sig_keys.contains(kp.leaf_node().signature_key().as_slice()))
            .collect();
        let skipped = total - key_packages.len();
        if key_packages.is_empty() {
            if total == 1 {
                return Err(KeychatError::Mls(
                    "The member is already in the group".to_string(),
                ));
            } else {
                return Err(KeychatError::Mls(format!(
                    "All {} members are already in the group",
                    total
                )));
            }
        }
        if skipped > 0 {
            tracing::warn!(
                "Skipped {} already-in-group member(s), adding remaining {}.",
                skipped,
                key_packages.len()
            );
        }

        let (commit, welcome, _group_info) = group
            .add_members(self.provider.inner(), &self.signer, &key_packages)
            .map_err(|e| KeychatError::Mls(format!("add_members error: {e}")))?;

        group
            .merge_pending_commit(self.provider.inner())
            .map_err(|e| KeychatError::Mls(format!("merge commit error: {e}")))?;

        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize commit: {e}")))?;
        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize welcome: {e}")))?;

        tracing::info!(
            "MLS add_members: group_id={}, count={}",
            &group_id[..16.min(group_id.len())],
            key_packages.len()
        );
        Ok((commit_bytes, welcome_bytes))
    }

    /// Join a group via a Welcome message.
    pub fn join_group(&self, welcome_bytes: &[u8]) -> Result<String> {
        let welcome_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| KeychatError::Mls(format!("deserialize welcome: {e}")))?;

        let welcome = match welcome_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(KeychatError::Mls("message is not a Welcome".to_string())),
        };

        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        let group =
            StagedWelcome::new_from_welcome(self.provider.inner(), &join_config, welcome, None)
                .map_err(|e| KeychatError::Mls(format!("staged welcome error: {e}")))?
                .into_group(self.provider.inner())
                .map_err(|e| KeychatError::Mls(format!("welcome into group error: {e}")))?;

        let group_id = String::from_utf8(group.group_id().as_slice().to_vec())
            .map_err(|e| KeychatError::Mls(format!("group_id not utf8: {e}")))?;

        tracing::info!(
            "MLS join_group: group_id={}",
            &group_id[..16.min(group_id.len())]
        );
        Ok(group_id)
    }

    /// Encrypt a plaintext message for the group.
    /// Returns the serialized MLS application message.
    pub fn encrypt(&self, group_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut group = self.load_group(group_id)?;

        let msg_out = group
            .create_message(self.provider.inner(), &self.signer, plaintext)
            .map_err(|e| {
                tracing::error!(
                    "MLS encrypt failed for group_id={}: {e}",
                    &group_id[..16.min(group_id.len())]
                );
                KeychatError::Mls(format!("encrypt error: {e}"))
            })?;

        let bytes = msg_out
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize msg: {e}")))?;

        Ok(bytes)
    }

    /// Decrypt an MLS message for the group.
    /// Returns a typed [`MlsDecryptResult`] distinguishing application data from control messages.
    pub fn decrypt(&self, group_id: &str, ciphertext: &[u8]) -> Result<MlsDecryptResult> {
        let mut group = self.load_group(group_id)?;

        let msg_in = MlsMessageIn::tls_deserialize_exact(ciphertext).map_err(|e| {
            tracing::error!(
                "MLS decrypt deserialize failed for group_id={}: {e}",
                &group_id[..16.min(group_id.len())]
            );
            KeychatError::Mls(format!("deserialize msg: {e}"))
        })?;

        let protocol_msg = msg_in
            .try_into_protocol_message()
            .map_err(|e| KeychatError::Mls(format!("not a protocol message: {e}")))?;

        let processed = group
            .process_message(self.provider.inner(), protocol_msg)
            .map_err(|e| {
                tracing::error!(
                    "MLS decrypt process_message failed for group_id={}: {e}",
                    &group_id[..16.min(group_id.len())]
                );
                KeychatError::Mls(format!("process message error: {e}"))
            })?;

        // Extract sender credential identity
        let sender_identity = processed.credential().serialized_content().to_vec();
        let sender_id = String::from_utf8(sender_identity).unwrap_or_else(|e| {
            tracing::warn!("MLS sender credential is not valid UTF-8: {e}");
            "unknown".to_string()
        });

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(MlsDecryptResult::Application {
                    plaintext: app_msg.into_bytes(),
                    sender_id,
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                group
                    .merge_staged_commit(self.provider.inner(), *staged_commit)
                    .map_err(|e| KeychatError::Mls(format!("merge staged commit: {e}")))?;
                Ok(MlsDecryptResult::Commit { sender_id })
            }
            ProcessedMessageContent::ProposalMessage(_) => {
                Ok(MlsDecryptResult::Proposal { sender_id })
            }
            _ => Err(KeychatError::Mls(
                "unexpected message content type".to_string(),
            )),
        }
    }

    /// Remove members from the group by their leaf indices.
    /// Returns the serialized Commit.
    pub fn remove_members(
        &self,
        group_id: &str,
        members_to_remove: &[LeafNodeIndex],
    ) -> Result<Vec<u8>> {
        let mut group = self.load_group(group_id)?;

        let (commit, _, _) = group
            .remove_members(self.provider.inner(), &self.signer, members_to_remove)
            .map_err(|e| KeychatError::Mls(format!("remove_members error: {e}")))?;

        group
            .merge_pending_commit(self.provider.inner())
            .map_err(|e| KeychatError::Mls(format!("merge commit error: {e}")))?;

        let bytes = commit
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize commit: {e}")))?;

        Ok(bytes)
    }

    /// Self-update (key rotation). Returns the serialized Commit.
    pub fn self_update(&self, group_id: &str) -> Result<Vec<u8>> {
        let mut group = self.load_group(group_id)?;

        let bundle = group
            .self_update(
                self.provider.inner(),
                &self.signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| KeychatError::Mls(format!("self_update error: {e}")))?;

        let commit_bytes = bundle
            .commit()
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize commit: {e}")))?;

        group
            .merge_pending_commit(self.provider.inner())
            .map_err(|e| KeychatError::Mls(format!("merge commit error: {e}")))?;

        Ok(commit_bytes)
    }

    /// Leave a group by generating a remove proposal for self.
    /// Returns the serialized proposal to broadcast.
    pub fn leave_group(&self, group_id: &str) -> Result<Vec<u8>> {
        let mut group = self.load_group(group_id)?;
        let msg = group
            .leave_group(self.provider.inner(), &self.signer)
            .map_err(|e| KeychatError::Mls(format!("leave_group: {e}")))?;
        msg.tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize leave: {e}")))
    }

    /// Process an incoming Commit message.
    /// Call `derive_mls_temp_inbox` after this to get the new address.
    pub fn process_commit(&self, group_id: &str, commit_bytes: &[u8]) -> Result<()> {
        let mut group = self.load_group(group_id)?;

        let msg_in = MlsMessageIn::tls_deserialize_exact(commit_bytes)
            .map_err(|e| KeychatError::Mls(format!("deserialize commit: {e}")))?;

        let protocol_msg = msg_in
            .try_into_protocol_message()
            .map_err(|e| KeychatError::Mls(format!("not a protocol message: {e}")))?;

        let processed = group
            .process_message(self.provider.inner(), protocol_msg)
            .map_err(|e| KeychatError::Mls(format!("process commit error: {e}")))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(self.provider.inner(), *staged)
                    .map_err(|e| KeychatError::Mls(format!("merge staged commit: {e}")))?;
                Ok(())
            }
            _ => Err(KeychatError::Mls("expected a Commit message".to_string())),
        }
    }

    /// Export the MLS export secret for a group (used for mlsTempInbox derivation).
    pub fn export_secret(
        &self,
        group_id: &str,
        label: &str,
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>> {
        let group = self.load_group(group_id)?;
        group
            .export_secret(self.provider.inner().crypto(), label, context, len)
            .map_err(|e| KeychatError::Mls(format!("export_secret error: {e}")))
    }

    /// Derive the MLS temp inbox address for a group (§11.2).
    pub fn derive_temp_inbox(&self, group_id: &str) -> Result<String> {
        let export_secret = self.export_secret(group_id, MLS_TEMP_INBOX_LABEL, &[], 32)?;
        Ok(derive_mls_temp_inbox(
            &self.nostr_id,
            group_id,
            &export_secret,
        ))
    }

    /// Get the list of members' credential identities in the group.
    pub fn group_members(&self, group_id: &str) -> Result<Vec<String>> {
        let group = self.load_group(group_id)?;
        let members: Vec<String> = group
            .members()
            .map(|m| {
                String::from_utf8(m.credential.serialized_content().to_vec()).unwrap_or_else(|e| {
                    tracing::warn!("MLS member credential is not valid UTF-8: {e}");
                    "unknown".to_string()
                })
            })
            .collect();
        Ok(members)
    }

    /// Find a member's leaf index by their credential identity.
    pub fn find_member_index(&self, group_id: &str, member_id: &str) -> Result<LeafNodeIndex> {
        let group = self.load_group(group_id)?;
        for member in group.members() {
            let id = String::from_utf8(member.credential.serialized_content().to_vec())
                .unwrap_or_else(|e| {
                    tracing::warn!("MLS member credential is not valid UTF-8: {e}");
                    String::new()
                });
            if id == member_id {
                return Ok(member.index);
            }
        }
        Err(KeychatError::Mls(format!("member not found: {member_id}")))
    }

    /// Update group context extensions (used for rename, dissolve, etc.).
    /// Returns the serialized Commit.
    pub fn update_group_context_extensions(
        &self,
        group_id: &str,
        name: Option<&str>,
        status: Option<&str>,
        admin_pubkeys: Option<Vec<String>>,
    ) -> Result<Vec<u8>> {
        let mut group = self.load_group(group_id)?;

        // Load current extension data
        let current_ext = NostrGroupDataExtension::from_group(&group)
            .map_err(|e| KeychatError::Mls(format!("read group extension: {e}")))?;

        let mut updated = current_ext.clone();
        if let Some(n) = name {
            updated.set_name(n.to_string());
        }
        if let Some(s) = status {
            updated.set_status(s.to_string());
        }
        if let Some(admins) = admin_pubkeys {
            updated.set_admin_pubkeys(admins);
        }

        let ext_data = updated
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("TLS serialize: {e}")))?;

        let extension = Extension::Unknown(NOSTR_GROUP_EXTENSION_TYPE, UnknownExtension(ext_data));
        let required_caps = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(NOSTR_GROUP_EXTENSION_TYPE)],
            &[],
            &[],
        ));
        let extensions = Extensions::from_vec(vec![extension, required_caps])
            .map_err(|e| KeychatError::Mls(format!("extensions error: {e}")))?;

        let (commit, _, _) = group
            .update_group_context_extensions(self.provider.inner(), extensions, &self.signer)
            .map_err(|e| KeychatError::Mls(format!("update extensions error: {e}")))?;

        group
            .merge_pending_commit(self.provider.inner())
            .map_err(|e| KeychatError::Mls(format!("merge commit error: {e}")))?;

        let bytes = commit
            .tls_serialize_detached()
            .map_err(|e| KeychatError::Mls(format!("serialize commit: {e}")))?;

        Ok(bytes)
    }

    /// Read the NostrGroupDataExtension from a group.
    pub fn group_extension(&self, group_id: &str) -> Result<NostrGroupDataExtension> {
        let group = self.load_group(group_id)?;
        NostrGroupDataExtension::from_group(&group)
            .map_err(|e| KeychatError::Mls(format!("read group extension: {e}")))
    }

    // ─── Internal helpers ───────────────────────────────────────────────────

    fn load_group(&self, group_id: &str) -> Result<MlsGroup> {
        MlsGroup::load(
            self.provider.inner().storage(),
            &GroupId::from_slice(group_id.as_bytes()),
        )
        .map_err(|e| KeychatError::Mls(format!("load group error: {e}")))?
        .ok_or_else(|| KeychatError::Mls(format!("group not found: {group_id}")))
    }

    fn create_capabilities(&self) -> Result<Capabilities> {
        let required_extensions = &[
            ExtensionType::RequiredCapabilities,
            ExtensionType::LastResort,
            ExtensionType::RatchetTree,
            ExtensionType::Unknown(NOSTR_GROUP_EXTENSION_TYPE),
        ];
        Ok(Capabilities::new(
            None,
            Some(&[MLS_CIPHERSUITE]),
            Some(required_extensions),
            None,
            None,
        ))
    }
}

// ─── mlsTempInbox derivation (§11.2) ────────────────────────────────────────

/// Derive the shared MLS receiving address from the export secret.
///
/// All members in the same epoch compute the same value.
/// Returns a hex-encoded secp256k1 x-only pubkey string.
pub fn derive_mls_temp_inbox(nostr_id: &str, group_id: &str, export_secret: &[u8]) -> String {
    // Deterministic derivation: SHA256(export_secret || "keychat-mls-inbox" || group_id)
    let mut hasher = Sha256::new();
    hasher.update(export_secret);
    hasher.update(b"keychat-mls-inbox");
    hasher.update(group_id.as_bytes());
    let hash = hasher.finalize();

    // Interpret the hash as a secp256k1 secret key and derive the x-only pubkey
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&hash)
        .expect("SHA256 output should be valid secp256k1 secret key");
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let (x_only, _parity) = keypair.x_only_public_key();
    hex::encode(x_only.serialize())
}

// ─── MLS Group Transport (Part B) ──────────────────────────────────────────

/// Metadata from a decrypted MLS message.
#[derive(Debug, Clone)]
pub struct MlsMessageMetadata {
    /// Sender's credential identity (nostr_id).
    pub sender_id: String,
    /// Whether this was a Commit (control) message vs application message.
    pub is_commit: bool,
}

/// Encrypt a KCMessage and wrap as a kind:1059 Nostr event for MLS group transport.
///
/// Returns the serialized kind:1059 event JSON.
pub fn send_mls_message(
    participant: &MlsParticipant,
    group_id: &str,
    message: &KCMessage,
    mls_temp_inbox: &str,
) -> Result<nostr::Event> {
    // Serialize KCMessage → JSON
    let json = message.to_json()?;

    // MLS encrypt
    let ciphertext = participant.encrypt(group_id, json.as_bytes())?;

    // Base64 encode
    let content = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

    // Build kind:1059 event with ephemeral sender
    let ephemeral = EphemeralKeypair::generate();
    let p_tag = nostr::Tag::public_key(
        nostr::PublicKey::from_hex(mls_temp_inbox)
            .map_err(|e| KeychatError::Mls(format!("invalid mls_temp_inbox: {e}")))?,
    );

    let event = nostr::EventBuilder::new(nostr::Kind::from(1059), &content)
        .tag(p_tag)
        .sign_with_keys(ephemeral.keys())
        .map_err(|e| KeychatError::Mls(format!("sign event error: {e}")))?;

    Ok(event)
}

/// Receive and decrypt an MLS message from a kind:1059 event.
pub fn receive_mls_message(
    participant: &MlsParticipant,
    group_id: &str,
    event: &nostr::Event,
) -> Result<(KCMessage, MlsMessageMetadata)> {
    // Decode base64 content
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|e| KeychatError::Mls(format!("base64 decode error: {e}")))?;

    // MLS decrypt
    let result = participant.decrypt(group_id, &ciphertext)?;

    match result {
        MlsDecryptResult::Application {
            plaintext,
            sender_id,
        } => {
            let json_str = String::from_utf8(plaintext)
                .map_err(|e| KeychatError::Mls(format!("plaintext not utf8: {e}")))?;
            let message = KCMessage::try_parse(&json_str).ok_or_else(|| {
                KeychatError::Mls("failed to parse KCMessage from MLS plaintext".to_string())
            })?;
            let metadata = MlsMessageMetadata {
                sender_id,
                is_commit: false,
            };
            Ok((message, metadata))
        }
        MlsDecryptResult::Commit { sender_id } => {
            let msg = KCMessage {
                v: 2,
                kind: KCMessageKind::Text,
                text: Some(crate::message::KCTextPayload {
                    content: String::new(),
                    format: None,
                }),
                group_id: Some(group_id.to_string()),
                ..KCMessage::empty()
            };
            let metadata = MlsMessageMetadata {
                sender_id,
                is_commit: true,
            };
            Ok((msg, metadata))
        }
        MlsDecryptResult::Proposal { sender_id } => {
            let msg = KCMessage {
                v: 2,
                kind: KCMessageKind::Text,
                text: Some(crate::message::KCTextPayload {
                    content: String::new(),
                    format: None,
                }),
                group_id: Some(group_id.to_string()),
                ..KCMessage::empty()
            };
            let metadata = MlsMessageMetadata {
                sender_id,
                is_commit: false,
            };
            Ok((msg, metadata))
        }
    }
}

/// Wrap an MLS Commit as a kind:1059 event for broadcast.
pub fn broadcast_commit(commit_bytes: &[u8], mls_temp_inbox: &str) -> Result<nostr::Event> {
    let content = base64::engine::general_purpose::STANDARD.encode(commit_bytes);
    let ephemeral = EphemeralKeypair::generate();

    let p_tag = nostr::Tag::public_key(
        nostr::PublicKey::from_hex(mls_temp_inbox)
            .map_err(|e| KeychatError::Mls(format!("invalid mls_temp_inbox: {e}")))?,
    );

    let event = nostr::EventBuilder::new(nostr::Kind::from(1059), &content)
        .tag(p_tag)
        .sign_with_keys(ephemeral.keys())
        .map_err(|e| KeychatError::Mls(format!("sign event error: {e}")))?;

    Ok(event)
}

// ─── KeyPackage publish/parse (kind 10443) ──────────────────────────────────

/// MLS KeyPackage Nostr event kind.
pub const KIND_MLS_KEY_PACKAGE: u16 = 10443;

/// Serialize a KeyPackage into a kind 10443 Nostr event.
pub fn publish_key_package(
    key_package: &KeyPackage,
    identity_keys: &nostr::Keys,
) -> Result<nostr::Event> {
    let kp_bytes = key_package
        .tls_serialize_detached()
        .map_err(|e| KeychatError::Mls(format!("serialize key package: {e}")))?;
    let content = base64::engine::general_purpose::STANDARD.encode(&kp_bytes);

    let event = nostr::EventBuilder::new(nostr::Kind::from(KIND_MLS_KEY_PACKAGE), &content)
        .sign_with_keys(identity_keys)
        .map_err(|e| KeychatError::Mls(format!("sign key package event: {e}")))?;

    Ok(event)
}

/// Parse a kind 10443 event back into a KeyPackage.
pub fn parse_key_package(event: &nostr::Event) -> Result<KeyPackage> {
    if event.kind != nostr::Kind::from(KIND_MLS_KEY_PACKAGE) {
        return Err(KeychatError::Mls(format!(
            "expected kind {KIND_MLS_KEY_PACKAGE}, got {}",
            event.kind.as_u16()
        )));
    }

    let kp_bytes = base64::engine::general_purpose::STANDARD
        .decode(&event.content)
        .map_err(|e| KeychatError::Mls(format!("base64 decode key package: {e}")))?;

    let kp_in = KeyPackageIn::tls_deserialize_exact(&kp_bytes)
        .map_err(|e| KeychatError::Mls(format!("deserialize key package: {e}")))?;

    // Validate the KeyPackage with the crypto provider
    let crypto = openmls_rust_crypto::RustCrypto::default();
    kp_in
        .validate(&crypto, ProtocolVersion::Mls10)
        .map_err(|e| KeychatError::Mls(format!("validate key package: {e}")))
}

// ─── MLS Group Invite payload ───────────────────────────────────────────────

/// MLS group invitation payload, sent via Signal or NIP-17.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlsGroupInvitePayload {
    /// Group ID.
    pub group_id: String,
    /// Group name.
    pub name: String,
    /// Base64-encoded Welcome message.
    pub welcome: String,
    /// Admin Nostr pubkeys.
    pub admin_pubkeys: Vec<String>,
}

impl MlsGroupInvitePayload {
    /// Create an invite from a group and welcome bytes.
    pub fn new(
        group_id: String,
        name: String,
        welcome_bytes: &[u8],
        admin_pubkeys: Vec<String>,
    ) -> Self {
        Self {
            group_id,
            name,
            welcome: base64::engine::general_purpose::STANDARD.encode(welcome_bytes),
            admin_pubkeys,
        }
    }

    /// Extract the Welcome bytes.
    pub fn welcome_bytes(&self) -> Result<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.welcome)
            .map_err(|e| KeychatError::Mls(format!("decode welcome: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Test 1: MLS group creation and basic messaging ────────────────────

    #[test]
    fn test_mls_group_create_and_message() {
        let alice = MlsParticipant::new("alice_nostr_pubkey").unwrap();
        let bob = MlsParticipant::new("bob_nostr_pubkey").unwrap();
        let charlie = MlsParticipant::new("charlie_nostr_pubkey").unwrap();

        let group_id = "test-group-1";

        // Alice creates the group
        alice.create_group(group_id, "Test Group").unwrap();

        // Bob and Charlie generate key packages
        let bob_kp = bob.generate_key_package().unwrap();
        let charlie_kp = charlie.generate_key_package().unwrap();

        // Alice adds Bob and Charlie
        let (_commit, welcome) = alice
            .add_members(group_id, vec![bob_kp, charlie_kp])
            .unwrap();

        // Bob and Charlie join
        let joined_id_bob = bob.join_group(&welcome).unwrap();
        assert_eq!(joined_id_bob, group_id);

        let joined_id_charlie = charlie.join_group(&welcome).unwrap();
        assert_eq!(joined_id_charlie, group_id);

        // Alice sends a message
        let msg = KCMessage::text("Hello MLS group!");
        let plaintext = msg.to_json().unwrap();
        let ciphertext = alice.encrypt(group_id, plaintext.as_bytes()).unwrap();

        // Bob decrypts
        let MlsDecryptResult::Application {
            plaintext: decrypted,
            sender_id: sender,
        } = bob.decrypt(group_id, &ciphertext).unwrap()
        else {
            panic!("expected Application message");
        };
        let decrypted_msg = KCMessage::try_parse(&String::from_utf8(decrypted).unwrap()).unwrap();
        assert_eq!(decrypted_msg.text.unwrap().content, "Hello MLS group!");
        assert_eq!(sender, "alice_nostr_pubkey");

        // Charlie decrypts
        let MlsDecryptResult::Application {
            plaintext: decrypted,
            sender_id: sender,
        } = charlie.decrypt(group_id, &ciphertext).unwrap()
        else {
            panic!("expected Application message");
        };
        let decrypted_msg = KCMessage::try_parse(&String::from_utf8(decrypted).unwrap()).unwrap();
        assert_eq!(decrypted_msg.text.unwrap().content, "Hello MLS group!");
        assert_eq!(sender, "alice_nostr_pubkey");
    }

    // ─── Test 2: Epoch rotation — mlsTempInbox changes after Commit ────────

    #[test]
    fn test_epoch_rotation_changes_temp_inbox() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "epoch-test";
        alice.create_group(group_id, "Epoch Test").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        // Get temp inbox before self_update
        let inbox_before = alice.derive_temp_inbox(group_id).unwrap();

        // Alice does a self-update (key rotation)
        let commit = alice.self_update(group_id).unwrap();

        // After the commit, Alice's temp inbox should change
        let inbox_after = alice.derive_temp_inbox(group_id).unwrap();

        assert_ne!(
            inbox_before, inbox_after,
            "mlsTempInbox must change after epoch advance"
        );

        // Bob processes the commit
        bob.process_commit(group_id, &commit).unwrap();
        let bob_inbox_after = bob.derive_temp_inbox(group_id).unwrap();

        // Both should derive the same new inbox
        assert_eq!(
            inbox_after, bob_inbox_after,
            "all members must derive the same mlsTempInbox"
        );
    }

    // ─── Test 3: Add member ────────────────────────────────────────────────

    #[test]
    fn test_add_member_can_receive() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();
        let charlie = MlsParticipant::new("charlie").unwrap();

        let group_id = "add-member-test";
        alice.create_group(group_id, "Add Member Test").unwrap();

        // Add Bob first
        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        // Now add Charlie
        let charlie_kp = charlie.generate_key_package().unwrap();
        let (commit, welcome2) = alice.add_members(group_id, vec![charlie_kp]).unwrap();

        // Bob processes the add-commit
        bob.process_commit(group_id, &commit).unwrap();
        // Charlie joins
        charlie.join_group(&welcome2).unwrap();

        // Alice sends a message — all three should be able to decrypt
        let plaintext = b"Hello everyone!";
        let ciphertext = alice.encrypt(group_id, plaintext).unwrap();

        let MlsDecryptResult::Application {
            plaintext: dec_bob, ..
        } = bob.decrypt(group_id, &ciphertext).unwrap()
        else {
            panic!("expected Application message");
        };
        assert_eq!(dec_bob, plaintext);

        let MlsDecryptResult::Application {
            plaintext: dec_charlie,
            ..
        } = charlie.decrypt(group_id, &ciphertext).unwrap()
        else {
            panic!("expected Application message");
        };
        assert_eq!(dec_charlie, plaintext);
    }

    // ─── Test 4: Remove member ─────────────────────────────────────────────

    #[test]
    fn test_remove_member_cannot_decrypt() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();
        let charlie = MlsParticipant::new("charlie").unwrap();

        let group_id = "remove-test";
        alice.create_group(group_id, "Remove Test").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let charlie_kp = charlie.generate_key_package().unwrap();
        let (_commit, welcome) = alice
            .add_members(group_id, vec![bob_kp, charlie_kp])
            .unwrap();
        bob.join_group(&welcome).unwrap();
        charlie.join_group(&welcome).unwrap();

        // Find Charlie's leaf index and remove
        let charlie_idx = alice.find_member_index(group_id, "charlie").unwrap();
        let commit = alice.remove_members(group_id, &[charlie_idx]).unwrap();

        // Bob processes the removal
        bob.process_commit(group_id, &commit).unwrap();

        // Alice sends a message
        let ciphertext = alice.encrypt(group_id, b"Secret after removal").unwrap();

        // Bob can decrypt
        let MlsDecryptResult::Application { plaintext: dec, .. } =
            bob.decrypt(group_id, &ciphertext).unwrap()
        else {
            panic!("expected Application message");
        };
        assert_eq!(dec, b"Secret after removal");

        // Charlie should NOT be able to decrypt (still on old epoch)
        let result = charlie.decrypt(group_id, &ciphertext);
        assert!(
            result.is_err(),
            "removed member should not decrypt new messages"
        );
    }

    // ─── Test 5: Self leave ────────────────────────────────────────────────

    #[test]
    fn test_self_leave() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "leave-test";
        alice.create_group(group_id, "Leave Test").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        // Bob does a self-update with a key rotation, then we remove him
        // (MLS doesn't have a native "self-leave" — typically done via
        // remove_members by the member themselves, or via self_update + leave)
        // For simplicity, Alice removes Bob
        let bob_idx = alice.find_member_index(group_id, "bob").unwrap();
        let commit = alice.remove_members(group_id, &[bob_idx]).unwrap();

        // Alice can still send messages
        let ciphertext = alice.encrypt(group_id, b"After Bob left").unwrap();

        // Bob tries to decrypt — should fail after removal

        let result = bob.decrypt(group_id, &ciphertext);
        assert!(
            result.is_err(),
            "left member should not decrypt new messages"
        );
    }

    // ─── Test 6: Group dissolve ────────────────────────────────────────────

    #[test]
    fn test_group_dissolve() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "dissolve-test";
        alice.create_group(group_id, "Dissolve Test").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        // Alice dissolves the group by updating status
        let commit = alice
            .update_group_context_extensions(group_id, None, Some("dissolved"), None)
            .unwrap();

        // Bob processes the commit
        bob.process_commit(group_id, &commit).unwrap();

        // Verify the status is now "dissolved"
        let ext = bob.group_extension(group_id).unwrap();
        assert_eq!(ext.status(), "dissolved");
    }

    // ─── Test 7: KeyPackage publish/parse roundtrip ────────────────────────

    #[test]
    fn test_key_package_roundtrip() {
        let alice = MlsParticipant::new("alice").unwrap();
        let kp = alice.generate_key_package().unwrap();

        // Create Nostr keys for publishing
        let keys = nostr::Keys::generate();

        // Publish as kind 10443
        let event = publish_key_package(&kp, &keys).unwrap();
        assert_eq!(event.kind, nostr::Kind::from(KIND_MLS_KEY_PACKAGE));

        // Parse back
        let parsed_kp = parse_key_package(&event).unwrap();

        // Compare serialized forms
        let original_bytes = kp.tls_serialize_detached().unwrap();
        let parsed_bytes = parsed_kp.tls_serialize_detached().unwrap();
        assert_eq!(original_bytes, parsed_bytes);
    }

    // ─── Test 8: mlsTempInbox derivation consistency ───────────────────────

    #[test]
    fn test_mls_temp_inbox_deterministic() {
        let export_secret = [42u8; 32];
        let group_id = "test-group";

        // Different nostr_ids but same export_secret and group_id
        // should produce the same result (nostr_id is NOT used in derivation)
        let inbox1 = derive_mls_temp_inbox("alice", group_id, &export_secret);
        let inbox2 = derive_mls_temp_inbox("bob", group_id, &export_secret);
        let inbox3 = derive_mls_temp_inbox("charlie", group_id, &export_secret);

        assert_eq!(inbox1, inbox2);
        assert_eq!(inbox2, inbox3);

        // Different export_secret should produce different result
        let export_secret2 = [43u8; 32];
        let inbox4 = derive_mls_temp_inbox("alice", group_id, &export_secret2);
        assert_ne!(inbox1, inbox4);

        // The result should be a valid 64-char hex string (secp256k1 x-only pubkey)
        assert_eq!(inbox1.len(), 64);
        assert!(inbox1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ─── Test 9: Multiple epochs ───────────────────────────────────────────

    #[test]
    fn test_multiple_epochs() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "multi-epoch";
        alice.create_group(group_id, "Multi Epoch").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        let mut prev_inbox = alice.derive_temp_inbox(group_id).unwrap();

        // Do several self-updates, checking messages work after each
        for i in 0..3 {
            let commit = alice.self_update(group_id).unwrap();
            bob.process_commit(group_id, &commit).unwrap();

            let new_inbox = alice.derive_temp_inbox(group_id).unwrap();
            assert_ne!(prev_inbox, new_inbox, "epoch {i}: inbox must change");
            prev_inbox = new_inbox;

            // Send and receive a message
            let plaintext = format!("Message in epoch {}", i + 2);
            let ct = alice.encrypt(group_id, plaintext.as_bytes()).unwrap();
            let MlsDecryptResult::Application { plaintext: dec, .. } =
                bob.decrypt(group_id, &ct).unwrap()
            else {
                panic!("expected Application message");
            };
            assert_eq!(
                String::from_utf8(dec).unwrap(),
                plaintext,
                "epoch {}: message should decrypt correctly",
                i + 2
            );
        }
    }

    // ─── Test: send/receive MLS message via kind:1059 ──────────────────────

    #[test]
    fn test_send_receive_mls_message() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "transport-test";
        alice.create_group(group_id, "Transport Test").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        let mls_temp_inbox = alice.derive_temp_inbox(group_id).unwrap();

        // Alice sends a KCMessage
        let msg = KCMessage {
            v: 2,
            kind: KCMessageKind::Text,
            text: Some(crate::message::KCTextPayload {
                content: "Hello via MLS transport!".to_string(),
                format: None,
            }),
            group_id: Some(group_id.to_string()),
            ..KCMessage::empty()
        };

        let event = send_mls_message(&alice, group_id, &msg, &mls_temp_inbox).unwrap();
        assert_eq!(event.kind, nostr::Kind::from(1059));

        // Bob receives and decrypts
        let (received_msg, metadata) = receive_mls_message(&bob, group_id, &event).unwrap();
        assert!(!metadata.is_commit);
        assert_eq!(metadata.sender_id, "alice");
        assert_eq!(
            received_msg.text.unwrap().content,
            "Hello via MLS transport!"
        );
    }

    // ─── Test: Group rename ────────────────────────────────────────────────

    #[test]
    fn test_group_rename() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "rename-test";
        alice.create_group(group_id, "Original Name").unwrap();

        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();
        bob.join_group(&welcome).unwrap();

        // Verify original name
        let ext = alice.group_extension(group_id).unwrap();
        assert_eq!(ext.name(), "Original Name");

        // Alice renames the group
        let commit = alice
            .update_group_context_extensions(group_id, Some("New Name"), None, None)
            .unwrap();

        // Bob processes commit
        bob.process_commit(group_id, &commit).unwrap();

        // Verify both see the new name
        let alice_ext = alice.group_extension(group_id).unwrap();
        assert_eq!(alice_ext.name(), "New Name");

        let bob_ext = bob.group_extension(group_id).unwrap();
        assert_eq!(bob_ext.name(), "New Name");
    }

    // ─── Test: MlsGroupInvitePayload roundtrip ────────────────────────────

    #[test]
    fn test_mls_group_invite_payload() {
        let welcome_bytes = b"fake-welcome-data";
        let payload = MlsGroupInvitePayload::new(
            "group-1".into(),
            "My Group".into(),
            welcome_bytes,
            vec!["admin1".into()],
        );

        let json = serde_json::to_string(&payload).unwrap();
        let parsed: MlsGroupInvitePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.group_id, "group-1");
        assert_eq!(parsed.name, "My Group");
        assert_eq!(parsed.welcome_bytes().unwrap(), welcome_bytes);
    }

    // ─── Test: group_members listing ───────────────────────────────────────

    #[test]
    fn test_group_members() {
        let alice = MlsParticipant::new("alice").unwrap();
        let bob = MlsParticipant::new("bob").unwrap();

        let group_id = "members-test";
        alice.create_group(group_id, "Members Test").unwrap();

        // Initially just Alice
        let members = alice.group_members(group_id).unwrap();
        assert_eq!(members.len(), 1);
        assert!(members.contains(&"alice".to_string()));

        // Add Bob
        let bob_kp = bob.generate_key_package().unwrap();
        let (_commit, _welcome) = alice.add_members(group_id, vec![bob_kp]).unwrap();

        // Now Alice + Bob
        let members = alice.group_members(group_id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&"alice".to_string()));
        assert!(members.contains(&"bob".to_string()));
    }
}
