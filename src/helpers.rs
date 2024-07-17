use openmls::credentials::{Credential, CredentialType, CredentialWithKey};
use openmls::key_packages::{KeyPackage, KeyPackageBundle};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::Ciphersuite;

pub fn generate_credential(id: &str, ciphersuite: Ciphersuite,
                           backend: &impl OpenMlsProvider) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(CredentialType::Basic, id.into());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Unable to generate signature keys");
    signature_keys.store(backend.storage()).expect("Error storing signature keys in key store.");
    (
        CredentialWithKey {
            credential,
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    )
}


pub fn generate_key_package(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackageBundle {
    let kp = KeyPackage::builder().build(ciphersuite, backend, signer, credential_with_key).unwrap();
    return kp;
}

pub fn bytes_to_string(bytes: Vec<u8>) -> String {
    let vec_to_string = String::from_utf8(bytes).unwrap();
    println!("bob receiving message from alice: {}", vec_to_string);
    return vec_to_string.to_string();
}

