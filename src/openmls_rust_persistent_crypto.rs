//! # OpenMLS Default Crypto Provider
//!
//! This is an implementation of the [`OpenMlsCryptoProvider`] trait to use with
//! OpenMLS.

use std::fs::File;
use std::path::Path;
use std::string::ToString;
use std::sync::Mutex;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::OpenMlsProvider;

#[derive(Default, Debug)]
pub struct OpenMlsRustPersistentCrypto {
    crypto: RustCrypto,
    storage: MemoryStorage,
}


static KEY_STORE_FILE: Mutex<String> = Mutex::new(String::new());


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
        let file_path = KEY_STORE_FILE.lock().unwrap().to_string();
        println!("the keystore file path is now {file_path}");
        let file = File::create(file_path).expect("unable to create keystore file");
        self.storage.save_to_file(&file).expect("unable to save keystore");
        drop(file);
    }

    pub fn load_keystore(&mut self) {
        let file_path = KEY_STORE_FILE.lock().unwrap().to_string();
        println!("the keystore file path is now {file_path}");
        let file = File::open(file_path).expect("unable to open keystore file");
        self.storage.load_from_file(&file).expect("unable to load keystore");
    }

    pub fn init(&mut self) {
        if Path::new(&KEY_STORE_FILE.lock().unwrap().to_string()).exists() {
            self.load_keystore();
        }
    }

    pub fn set_key_store_file_path(&mut self, file_path: &str){
        *KEY_STORE_FILE.lock().unwrap() = file_path.to_string();
        let file_path = KEY_STORE_FILE.lock().unwrap().to_string();
        println!("the keystore file path is now {file_path}");
    }
}
