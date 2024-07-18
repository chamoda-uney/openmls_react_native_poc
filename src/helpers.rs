use openmls::credentials::{Credential, CredentialType, CredentialWithKey};
use openmls::key_packages::{KeyPackage, KeyPackageBundle};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::types::Ciphersuite;
use serde_json::{from_str, to_string};
use crate::structs::{InvitedMemberData, RegisteredUserData};

pub fn generate_credential(id: &str, ciphersuite: Ciphersuite,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(CredentialType::Basic, id.into());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("Unable to generate signature keys");
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
    return vec_to_string.to_string();
}

//These are a helper function needed for tests
pub fn _get_bobs_key_package_as_json_string(bobs_registered_user_data: &str) -> String {
    let registered_user_data: RegisteredUserData = from_str(&bobs_registered_user_data).expect("TEST unable to convert string to RegisteredUserData");
    let bobs_key_package = registered_user_data.key_package;
    return to_string(&bobs_key_package).expect("TEST unable to convert Bobs key package to string");
}

pub fn _get_serialized_welcome_message_out(invited_member_data_json_str: &str) -> String {
    let invited_member_data: InvitedMemberData = from_str(&invited_member_data_json_str).expect("TEST unable to convert string to InvitedMemberData");
    let serialized_welcome_message_out = invited_member_data.serialized_welcome_out;
    return to_string(&serialized_welcome_message_out).expect("TEST unable to convert serialized_welcome_message_out to string");
}

pub fn _get_invite_updated_group(invited_member_data_json_str: &str) -> String {
    let invited_member_data: InvitedMemberData = from_str(&invited_member_data_json_str).expect("TEST unable to convert string to InvitedMemberData");
    let group_with_new_state = invited_member_data.mls_group;
    return to_string(&group_with_new_state).expect("TEST unable to convert group_with_new_state to string");
}

