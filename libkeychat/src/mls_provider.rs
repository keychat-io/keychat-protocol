//! OpenMLS provider with persistent SQLite storage.
//! Inlined from the keychat-io/openmls kc4 fork's `kc` crate.

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct OpenMlsRustPersistentCrypto {
    pub crypto: RustCrypto,
    pub storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl OpenMlsRustPersistentCrypto {
    pub async fn new(storage: SqliteStorageProvider<JsonCodec, Connection>) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }

    /// Open a file-backed MLS storage at `path`.
    pub fn open(path: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let connection = Connection::open(path)?;
        let mut storage = SqliteStorageProvider::new(connection);
        storage.run_migrations()?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }
}

impl OpenMlsRustPersistentCrypto {
    /// Create an in-memory MLS storage (fallible version).
    pub fn new_in_memory() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        let mut storage = SqliteStorageProvider::new(connection);
        storage.run_migrations()?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }
}

impl Default for OpenMlsRustPersistentCrypto {
    fn default() -> Self {
        Self::new_in_memory().expect("failed to create in-memory MLS storage")
    }
}

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
