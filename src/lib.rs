mod helpers;
mod structs;

uniffi::setup_scaffolding!();

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls::prelude::tls_codec::*;
use serde_json;
use serde_json::from_str;
use crate::helpers::{bytes_to_string, generate_credential, generate_key_package};
use crate::structs::{InvitedMemberData, RegisteredUserData};


/**
functions in this library related to MLS
---Main Functions----
1. Create User
    - create credential
    - create signature
    - create key package
    - export the key package

2. Create Group

3. Invite Member
    - return welcome, mls_message

4. Create Group From Welcome
    - process the incoming welcome message and create group

5. Create Application Message
    - return the application message

6. Process Protocol Message
    - return the processed message (plain text)
 */

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;


#[uniffi::export]
fn register_user(user_id: &str) -> String {
    let (credential_with_key,
        signer) = generate_credential(
        user_id.into(),
        CIPHERSUITE,
        &OpenMlsRustCrypto::default(),
    );
    let key_package_bundle = generate_key_package(CIPHERSUITE,
                                                  &OpenMlsRustCrypto::default(),
                                                  &signer,
                                                  credential_with_key.clone());
    let key_package = key_package_bundle.key_package().clone();

    let registered_user_data = RegisteredUserData {
        key_package: key_package.clone(),
        signer,
        credential_with_key,
    };

    let serialized = serde_json::to_string(&registered_user_data).expect("unable to convert RegisteredUserData to string");
    return serialized;
}
#[uniffi::export]
fn create_group(group_id: &str, registered_user_data_json_str: &str) -> String {
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");

    let group_config_create = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mls_group = MlsGroup::new_with_group_id(&OpenMlsRustCrypto::default(), &registered_user_data.signer,
                                                &group_config_create,
                                                GroupId::from_slice(group_id.as_bytes()),
                                                registered_user_data.credential_with_key).expect("unexpected error occurred in creating group");


    let serialized = serde_json::to_string(&mls_group).expect("unable to convert MLSGroup to string");
    return serialized;
}

#[uniffi::export]
fn invite_member(registered_user_data_json_str: &str, member_key_package_json_str: &str, mls_group_json_str: &str) -> String {
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");
    let member_key_package: KeyPackage = from_str(&member_key_package_json_str).expect("unable to convert string to KeyPackage");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");


    let (mls_message_out, welcome_out, _) = mls_group.add_members(&OpenMlsRustCrypto::default(),
                                                                  &registered_user_data.signer,
                                                                  &[member_key_package]).expect("Error adding member to group");

    //merge pending commit
    mls_group.merge_pending_commit(&OpenMlsRustCrypto::default()).expect("error merging pending commit");

    let invited_member_data = InvitedMemberData {
        serialized_welcome_out: welcome_out.tls_serialize_detached().expect("error serializing welcome_out"),
        serialized_mls_message_out: mls_message_out.tls_serialize_detached().expect("error serializing mls_message_out"),
        mls_group,
    };
    let serialized = serde_json::to_string(&invited_member_data).expect("unable to convert InvitedMemberData to string");
    return serialized;
}

#[uniffi::export]
fn create_group_from_welcome(serialized_welcome_message_json_str: &str) -> String {
    let serialized_welcome: Vec<u8> = from_str(serialized_welcome_message_json_str).expect("unable to convert serialized_welcome Vec<u8> to string");

    let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
        .expect("An unexpected error occurred deserialize serialized_welcome");

    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => unreachable!("Unexpected message type to create a group from welcome"),
    };


    //bob now can join the group
    let group_config_join = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mls_group = StagedWelcome::new_from_welcome(
        &OpenMlsRustCrypto::default(),
        &group_config_join,
        welcome,
        None,
    )
        .expect("failed to create staged join").into_group(&OpenMlsRustCrypto::default())
        .expect("failed to create MLSGroup by welcome");

    let serialized = serde_json::to_string(&mls_group).expect("unable to convert MLSGroup to string");
    return serialized;
}

#[uniffi::export]
fn create_application_message(registered_user_data_json_str: &str, mls_group_json_str: &str, message: &str) -> String {
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");

    let mls_message_out = mls_group
        .create_message(&OpenMlsRustCrypto::default(), &registered_user_data.signer, message.as_bytes())
        .expect("error creating application message");

    let serialized = serde_json::to_string(&mls_message_out.to_bytes().expect("unable to serialize application message")).expect("unable to convert application MLSMessageOut Vec<u8> to string");
    return serialized;
}
#[uniffi::export]
fn process_application_message(mls_group_json_str: &str, serialized_application_message_json_str: &str) -> String {
    let serialized_application_message: Vec<u8> = from_str(serialized_application_message_json_str).expect("unable to convert serialized_application_message Vec<u8> to string");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");


    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_application_message).expect("could not deserialize MLSMessageIn message.");

    let protocol_message: ProtocolMessage = mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_message = mls_group
        .process_message(&OpenMlsRustCrypto::default(), protocol_message)
        .expect("could not process message.");


    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        return bytes_to_string(application_message.into_bytes());
    } else {
        panic!("Not an application message")
    }
}

/**
fn run_open_mls() {
    let BACKEND: &OpenMlsRustCrypto = &OpenMlsRustCrypto::default();

    // Alice credential
    let (alice_credential_with_key,
        alice_signer) = generate_credential(
        "Alice".into(),
        CIPHERSUITE,
        BACKEND,
    );

    // Bob credential
    let (bob_credential_with_key,
        bob_signer) = generate_credential(
        "Bob".into(),
        CIPHERSUITE,
        BACKEND,
    );

    //alice key package bundle
    //let alice_key_package_bundle = generate_key_package(CIPHERSUITE, BACKEND, &alice_signer, alice_credential_with_key);

    //bob key package bundle
    let bob_key_package_bundle = generate_key_package(CIPHERSUITE,
                                                      BACKEND,
                                                      &bob_signer,
                                                      bob_credential_with_key);


    //alice create the group
    //bob now can join the group
    let group_config_create = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice_group = MlsGroup::new(BACKEND, &alice_signer,
                                        &group_config_create,
                                        alice_credential_with_key).expect("unexpected error occurred in creating group");


    //alice invites bob
    let bob_key_package = bob_key_package_bundle.key_package().clone();
    let (_mls_message_out, welcome_out, _) = alice_group.add_members(BACKEND,
                                                                     &alice_signer,
                                                                     &[bob_key_package]).expect("Error adding member to group");

    //merge pending commit
    alice_group.merge_pending_commit(BACKEND).expect("error merging pending commit");

    //alice serialize the [`MlsMessageOut`] containing the [`Welcome`].
    let serialized_welcome = welcome_out.tls_serialize_detached().expect("error serializing");

    // bob can now de-serialize the message as an [`MlsMessageIn`] ...
    let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
        .expect("An unexpected error occurred.");

    // ... and inspect the message.
    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        // We know it's a welcome message, so we ignore all other cases.
        _ => unreachable!("Unexpected message type."),
    };


    //bob now can join the group
    let group_config_join = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_group = StagedWelcome::new_from_welcome(
        BACKEND,
        &group_config_join,
        welcome,
        None,
    )
        .expect("failed to create staged join").into_group(BACKEND)
        .expect("failed to create MLSGroup by welcome");


    /*-------------Group Established--------------*/

    //alice create message:
    let alice_message = b"Hi Bob. How are you!. I'm Alice...";
    let mls_message_out = alice_group
        .create_message(BACKEND, &alice_signer, alice_message)
        .expect("error creating application message for bob");


    //Bob process the message
    let serialized_application_message = mls_message_out.to_bytes().expect("unable to serialize application message");
    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_application_message).expect("could not deserialize message.");

    let protocol_message: ProtocolMessage = mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_message = bob_group
        .process_message(BACKEND, protocol_message)
        .expect("could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        bytes_to_string(application_message.into_bytes());
    } else {
        panic!("Not an application message")
    }
}
 */
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        /*  let res = register_user("chamoda");
          let grp = create_group("abc123", &res);*/
        println!();
    }
}
