mod group;
pub mod transport;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;

use group::{mls_err, random_group_id, ManagedUser};
use kc::openmls_rust_persistent_crypto::{JsonCodec, OpenMlsRustPersistentCrypto};
use lazy_static::lazy_static;
use openmls_sqlite_storage::{Connection, SqliteStorageProvider};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use crate::error::{KeychatError, Result};

pub use types::{
    AddMembersResult, CommitResult, CommitTypeResult, DecryptedGroupMessage, GroupMessage,
    KeyPackageResult, ProcessedMlsMessage, RemoveMemberResult,
};

struct MlsStore {
    users: HashMap<String, ManagedUser>,
}

pub struct MlsManager;

lazy_static! {
    static ref STORE: Mutex<Option<MlsStore>> = Mutex::new(None);
}

lazy_static! {
    static ref RUNTIME: Arc<Runtime> =
        Arc::new(Runtime::new().expect("failed to create MLS runtime"));
}

impl MlsManager {
    pub fn init_mls(db_path: &str, nostr_id: &str) -> Result<()> {
        init_mls(db_path, nostr_id)
    }

    pub fn create_key_package(nostr_id: &str) -> Result<KeyPackageResult> {
        create_key_package(nostr_id)
    }

    pub fn create_mls_group(nostr_id: &str, group_name: &str) -> Result<String> {
        create_mls_group(nostr_id, group_name)
    }

    pub fn add_member(
        nostr_id: &str,
        group_id: &str,
        key_package_hex: &str,
    ) -> Result<AddMembersResult> {
        add_member(nostr_id, group_id, key_package_hex)
    }

    pub fn join_group_from_welcome(nostr_id: &str, welcome_bytes: &[u8]) -> Result<String> {
        join_group_from_welcome(nostr_id, welcome_bytes)
    }

    pub fn remove_member(
        nostr_id: &str,
        group_id: &str,
        member_nostr_id: &str,
    ) -> Result<RemoveMemberResult> {
        remove_member(nostr_id, group_id, member_nostr_id)
    }

    pub fn leave_group(nostr_id: &str, group_id: &str) -> Result<Vec<u8>> {
        leave_group(nostr_id, group_id)
    }

    pub fn encrypt_group_message(nostr_id: &str, group_id: &str, message: &str) -> Result<Vec<u8>> {
        encrypt_group_message(nostr_id, group_id, message)
    }

    pub fn decrypt_group_message(
        nostr_id: &str,
        group_id: &str,
        ciphertext: &[u8],
    ) -> Result<DecryptedGroupMessage> {
        decrypt_group_message(nostr_id, group_id, ciphertext)
    }

    pub fn process_commit(
        nostr_id: &str,
        group_id: &str,
        commit_bytes: &[u8],
    ) -> Result<CommitResult> {
        process_commit(nostr_id, group_id, commit_bytes)
    }

    pub fn get_group_listen_key(nostr_id: &str, group_id: &str) -> Result<String> {
        get_group_listen_key(nostr_id, group_id)
    }

    pub fn list_groups(nostr_id: &str) -> Result<Vec<String>> {
        list_groups(nostr_id)
    }
}

pub fn init_mls(db_path: &str, nostr_id: &str) -> Result<()> {
    RUNTIME.block_on(async {
        let mut store = STORE.lock().await;
        let connection = Connection::open(db_path).map_err(mls_err)?;
        let mut storage = SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
        storage.initialize().map_err(mls_err)?;
        let provider = OpenMlsRustPersistentCrypto::new(storage).await;
        let user = ManagedUser::load(provider, nostr_id.to_owned()).await?;

        let users = store.get_or_insert_with(|| MlsStore {
            users: HashMap::new(),
        });
        users.users.insert(nostr_id.to_owned(), user);
        Ok(())
    })
}

pub fn create_key_package(nostr_id: &str) -> Result<KeyPackageResult> {
    with_user_mut(nostr_id, |user| user.create_key_package(), true)
}

pub fn create_mls_group(nostr_id: &str, group_name: &str) -> Result<String> {
    let group_name = group_name.to_owned();
    with_user_mut(
        nostr_id,
        move |user| {
            let group_id = random_group_id();
            user.create_group(group_id, &group_name)
        },
        false,
    )
}

pub fn add_member(
    nostr_id: &str,
    group_id: &str,
    key_package_hex: &str,
) -> Result<AddMembersResult> {
    let group_id = group_id.to_owned();
    let key_package_hex = key_package_hex.to_owned();
    with_user_mut(
        nostr_id,
        move |user| user.add_member(&group_id, &key_package_hex),
        false,
    )
}

pub fn join_group_from_welcome(nostr_id: &str, welcome_bytes: &[u8]) -> Result<String> {
    let welcome_bytes = welcome_bytes.to_vec();
    with_user_mut(
        nostr_id,
        move |user| user.join_group_from_welcome(&welcome_bytes),
        false,
    )
}

pub fn remove_member(
    nostr_id: &str,
    group_id: &str,
    member_nostr_id: &str,
) -> Result<RemoveMemberResult> {
    let group_id = group_id.to_owned();
    let member_nostr_id = member_nostr_id.to_owned();
    with_user_mut(
        nostr_id,
        move |user| user.remove_member(&group_id, &member_nostr_id),
        false,
    )
}

pub fn leave_group(nostr_id: &str, group_id: &str) -> Result<Vec<u8>> {
    let group_id = group_id.to_owned();
    with_user_mut(nostr_id, move |user| user.leave_group(&group_id), false)
}

pub fn encrypt_group_message(nostr_id: &str, group_id: &str, message: &str) -> Result<Vec<u8>> {
    let group_id = group_id.to_owned();
    let message = message.to_owned();
    with_user_mut(
        nostr_id,
        move |user| {
            user.encrypt_group_message(&group_id, &message)
                .map(|out| out.ciphertext)
        },
        false,
    )
}

pub fn decrypt_group_message(
    nostr_id: &str,
    group_id: &str,
    ciphertext: &[u8],
) -> Result<DecryptedGroupMessage> {
    let group_id = group_id.to_owned();
    let ciphertext = ciphertext.to_vec();
    with_user_mut(
        nostr_id,
        move |user| user.decrypt_group_message(&group_id, &ciphertext),
        false,
    )
}

pub fn process_commit(nostr_id: &str, group_id: &str, commit_bytes: &[u8]) -> Result<CommitResult> {
    let group_id = group_id.to_owned();
    let commit_bytes = commit_bytes.to_vec();
    with_user_mut(
        nostr_id,
        move |user| user.process_commit(&group_id, &commit_bytes),
        false,
    )
}

/// Process any inbound MLS message (application or commit) in a single call.
/// Preferred over separate `decrypt_group_message` / `process_commit` calls,
/// since `process_message` consumes epoch state on the first call.
pub fn process_mls_message(
    nostr_id: &str,
    group_id: &str,
    message_bytes: &[u8],
) -> Result<ProcessedMlsMessage> {
    let group_id = group_id.to_owned();
    let message_bytes = message_bytes.to_vec();
    with_user_mut(
        nostr_id,
        move |user| user.process_mls_message(&group_id, &message_bytes),
        false,
    )
}

pub fn get_export_secret_keypair(
    nostr_id: &str,
    group_id: &str,
) -> Result<crate::identity::NostrKeypair> {
    let group_id = group_id.to_owned();
    with_user_mut(
        nostr_id,
        move |user| user.get_export_secret_keypair(&group_id),
        false,
    )
}

pub fn get_group_listen_key(nostr_id: &str, group_id: &str) -> Result<String> {
    let group_id = group_id.to_owned();
    with_user_mut(
        nostr_id,
        move |user| user.get_group_listen_key(&group_id),
        false,
    )
}

pub fn list_groups(nostr_id: &str) -> Result<Vec<String>> {
    with_user(nostr_id, |user| Ok(user.list_groups()))
}

fn with_user<T, F>(nostr_id: &str, f: F) -> Result<T>
where
    F: FnOnce(&ManagedUser) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let nostr_id = nostr_id.to_owned();
    RUNTIME.block_on(async move {
        let store = STORE.lock().await;
        let store = store
            .as_ref()
            .ok_or_else(|| KeychatError::Mls("MLS store not initialized".to_owned()))?;
        let user = store
            .users
            .get(&nostr_id)
            .ok_or_else(|| KeychatError::MlsNotInitialized(nostr_id.clone()))?;
        f(user)
    })
}

fn with_user_mut<T, F>(nostr_id: &str, f: F, persist_identity: bool) -> Result<T>
where
    F: FnOnce(&mut ManagedUser) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let nostr_id = nostr_id.to_owned();
    RUNTIME.block_on(async move {
        let mut store = STORE.lock().await;
        let store = store
            .as_mut()
            .ok_or_else(|| KeychatError::Mls("MLS store not initialized".to_owned()))?;
        let user = store
            .users
            .get_mut(&nostr_id)
            .ok_or_else(|| KeychatError::MlsNotInitialized(nostr_id.clone()))?;
        let result = f(user)?;
        user.update(nostr_id, persist_identity).await?;
        Ok(result)
    })
}
