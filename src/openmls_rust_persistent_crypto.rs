//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use std::fs::File;
use std::path::Path;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

const KEY_STORE_PATH: &str = "openmls_keystore.json";

impl OpenMlsProvider for OpenMlsRustPersistentCrypto {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

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

impl OpenMlsRustPersistentCrypto {
    pub fn save_keystore(&self) {
        let file = File::create_new(KEY_STORE_PATH).expect("unable to create keystore file");
        self.storage.save_to_file(&file).expect("unable to save keystore");
        drop(file);
    }

    pub fn load_keystore(&mut self) {
        let file = File::open(KEY_STORE_PATH).expect("unable to open keystore file");
        self.storage.load_from_file(&file).expect("unable to load keystore");
    }

    pub fn init(&mut self) {
        if Path::new(KEY_STORE_PATH).exists() {
            self.load_keystore();
        }
    }
}
