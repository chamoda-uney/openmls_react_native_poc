use openmls::credentials::CredentialWithKey;
use openmls::key_packages::KeyPackage;
use openmls_basic_credential::SignatureKeyPair;

#[derive(serde::Serialize)]
#[derive(serde::Deserialize)]
pub struct RegisteredUserData {
    pub key_package: KeyPackage,
    pub signer: SignatureKeyPair,
    pub credential_with_key: CredentialWithKey,
}
#[derive(serde::Serialize)]
#[derive(serde::Deserialize)]
pub struct InvitedMemberData {
    pub serialized_welcome_out: Vec<u8>,
    pub serialized_mls_message_out: Vec<u8>
}