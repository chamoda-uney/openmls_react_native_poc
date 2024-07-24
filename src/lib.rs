mod helpers;
mod structs;
mod openmls_rust_persistent_crypto;

uniffi::setup_scaffolding!();

use openmls::prelude::*;
use openmls::prelude::tls_codec::*;
use serde_json;
use serde_json::from_str;
use crate::helpers::{bytes_to_string, generate_credential, generate_key_package};
use crate::openmls_rust_persistent_crypto::OpenMlsRustPersistentCrypto;
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


fn get_provider() -> OpenMlsRustPersistentCrypto {
    let mut provider = OpenMlsRustPersistentCrypto::default();
    provider.init();
    return provider;
}


#[uniffi::export]
fn mls_init(key_store_directory: String) {
    let mut provider = OpenMlsRustPersistentCrypto::default();
    provider.set_key_store_file_path(&key_store_directory);
}

#[uniffi::export]
fn mls_register_user(user_id: &str) -> String {
    let provider = get_provider();

    let (credential_with_key,
        signer) = generate_credential(
        user_id.into(),
        CIPHERSUITE,
    );
    let key_package_bundle = generate_key_package(CIPHERSUITE,
                                                  &provider,
                                                  &signer,
                                                  credential_with_key.clone());
    let key_package = key_package_bundle.key_package().clone();

    let registered_user_data = RegisteredUserData {
        key_package,
        signer,
        credential_with_key,
    };

    let serialized = serde_json::to_string(&registered_user_data).expect("unable to convert RegisteredUserData to string");

    provider.save_keystore(); //saving the keystore for future use (note, this is expiring in 3 months)

    return serialized;
}
#[uniffi::export]
fn mls_create_group(group_id: &str, registered_user_data_json_str: &str) -> String {
    let provider = get_provider();
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");

    let group_config_create = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let mls_group = MlsGroup::new_with_group_id(&provider, &registered_user_data.signer,
                                                &group_config_create,
                                                GroupId::from_slice(group_id.as_bytes()),
                                                registered_user_data.credential_with_key).expect("unexpected error occurred in creating group");


    let serialized = serde_json::to_string(&mls_group).expect("unable to convert MLSGroup to string");
    return serialized;
}

#[uniffi::export]
fn mls_invite_member(registered_user_data_json_str: &str, member_key_package_json_str: &str, mls_group_json_str: &str) -> String {
    let provider = get_provider();
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");
    let member_key_package: KeyPackage = from_str(&member_key_package_json_str).expect("unable to convert string to KeyPackage");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");


    let (mls_message_out, welcome_out, _) = mls_group.add_members(&provider,
                                                                  &registered_user_data.signer,
                                                                  &[member_key_package]).expect("Error adding member to group");

    //merge pending commit
    mls_group.merge_pending_commit(&provider).expect("error merging pending commit");

    let invited_member_data = InvitedMemberData {
        serialized_welcome_out: welcome_out.tls_serialize_detached().expect("error serializing welcome_out"),
        serialized_mls_message_out: mls_message_out.tls_serialize_detached().expect("error serializing mls_message_out"),
        mls_group,
    };
    let serialized = serde_json::to_string(&invited_member_data).expect("unable to convert InvitedMemberData to string");
    return serialized;
}

#[uniffi::export]
fn mls_create_group_from_welcome(serialized_welcome_message_json_str: &str) -> String {
    let provider = get_provider();

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
        &provider,
        &group_config_join,
        welcome,
        None,
    )
        .expect("failed to create staged join").into_group(&provider)
        .expect("failed to create MLSGroup by welcome");

    let serialized = serde_json::to_string(&mls_group).expect("unable to convert MLSGroup to string");
    return serialized;
}

#[uniffi::export]
fn mls_create_application_message(registered_user_data_json_str: &str, mls_group_json_str: &str, message: &str) -> String {
    let provider = get_provider();

    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");

    let mls_message_out = mls_group
        .create_message(&provider, &registered_user_data.signer, message.as_bytes())
        .expect("error creating application message");

    let serialized = serde_json::to_string(&mls_message_out.to_bytes().expect("unable to serialize application message")).expect("unable to convert application MLSMessageOut Vec<u8> to string");
    return serialized;
}
#[uniffi::export]
fn mls_process_application_message(mls_group_json_str: &str, serialized_application_message_json_str: &str) -> String {
    let provider = get_provider();

    let serialized_application_message: Vec<u8> = from_str(serialized_application_message_json_str).expect("unable to convert serialized_application_message Vec<u8> to string");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");


    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_application_message).expect("could not deserialize MLSMessageIn message.");

    let protocol_message: ProtocolMessage = mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_message = mls_group
        .process_message(&provider, protocol_message)
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

#[uniffi::export]
fn mls_process_commit_message(mls_group_json_str: &str, serialized_commit_message_json_str: &str) -> String {
    let provider = get_provider();

    let serialized_commit_message: Vec<u8> = from_str(serialized_commit_message_json_str).expect("unable to convert serialized_commit_message Vec<u8> to string");
    let mut mls_group: MlsGroup = from_str(&mls_group_json_str).expect("unable to convert string to MLSGroup");


    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_commit_message).expect("could not deserialize MLSMessageIn message.");

    let protocol_message: ProtocolMessage = mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_message = mls_group
        .process_message(&provider, protocol_message)
        .expect("could not process message.");


    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_message.into_content()
    {
        // Check the message
        // Merge staged commit
        mls_group
            .merge_staged_commit(&provider, *staged_commit)
            .expect("Error merging staged commit.");
        let serialized = serde_json::to_string(&mls_group).expect("unable to convert MLSGroup to string");
        return serialized;
    } else {
        panic!("Not an commit message")
    }
}


fn run_open_mls() {
    let provider_alice: &OpenMlsRustPersistentCrypto = &OpenMlsRustPersistentCrypto::default();

    let provider_bob: &OpenMlsRustPersistentCrypto = &OpenMlsRustPersistentCrypto::default();

    let provider_charlie: &OpenMlsRustPersistentCrypto = &OpenMlsRustPersistentCrypto::default();

    // Alice credential
    let (alice_credential_with_key,
        alice_signer) = generate_credential(
        "Alice".into(),
        CIPHERSUITE,
    );

    // Bob credential
    let (bob_credential_with_key,
        bob_signer) = generate_credential(
        "Bob".into(),
        CIPHERSUITE,
    );

    //Charlie credential
    let (charlie_credential_with_key,
        charlie_signer) = generate_credential(
        "Charlie".into(),
        CIPHERSUITE,
    );

    //alice key package bundle
    //let alice_key_package_bundle = generate_key_package(CIPHERSUITE, backend, &alice_signer, alice_credential_with_key);

    //bob key package bundle
    let bob_key_package_bundle = generate_key_package(CIPHERSUITE,
                                                      provider_bob,
                                                      &bob_signer,
                                                      bob_credential_with_key);

    //charlie key package bundle
    let charlie_key_package_bundle = generate_key_package(CIPHERSUITE,
                                                          provider_charlie,
                                                          &charlie_signer,
                                                          charlie_credential_with_key);


    //alice create the group
    //bob now can join the group
    let group_config_create = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice_group = MlsGroup::new(provider_alice, &alice_signer,
                                        &group_config_create,
                                        alice_credential_with_key).expect("unexpected error occurred in creating group");


    //alice invites bob
    let bob_key_package = bob_key_package_bundle.key_package().clone();
    let (_mls_message_out, welcome_out, _) = alice_group.add_members(provider_alice,
                                                                     &alice_signer,
                                                                     &[bob_key_package]).expect("Error adding member to group");

    //merge pending commit
    alice_group.merge_pending_commit(provider_alice).expect("error merging pending commit");

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
        provider_bob,
        &group_config_join,
        welcome,
        None,
    )
        .expect("failed to create staged join").into_group(provider_bob)
        .expect("failed to create MLSGroup by welcome");


    /*-------------Group Established--------------*/

    //alice create message:
    let alice_message = b"Hi Bob. How are you!. I'm Alice...";
    let mls_message_out = alice_group
        .create_message(provider_alice, &alice_signer, alice_message)
        .expect("error creating application message for bob");


    //Bob process the message
    let serialized_application_message = mls_message_out.to_bytes().expect("unable to serialize application message");
    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_application_message).expect("could not deserialize message.");

    let protocol_message: ProtocolMessage = mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_message = bob_group
        .process_message(provider_bob, protocol_message)
        .expect("could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        assert_eq!(bytes_to_string(application_message.into_bytes()), "Hi Bob. How are you!. I'm Alice...");
    } else {
        panic!("Not an application message")
    }

    /*-------------Invitation for 3rd member--------------*/

    //bob invite charlie to group
    let charlie_key_package = charlie_key_package_bundle.key_package().clone();
    let (mls_message_out_for_other_group_members, welcome_out_for_charlie, _) = bob_group.add_members(provider_bob,
                                                                                                      &bob_signer,
                                                                                                      &[charlie_key_package]).expect("Error adding member[charlie] to group");

    //merge pending commit [bob group]
    bob_group.merge_pending_commit(provider_bob).expect("error merging pending commit");


    //alice inspect the new commit message (charlie added commit) and merge the commit
    let serialized_commit_message = mls_message_out_for_other_group_members.to_bytes().expect("unable to serialize commit message");
    let mls_commit_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_commit_message).expect("could not deserialize message.");
    let protocol_commit_message: ProtocolMessage = mls_commit_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_commit_message = alice_group
        .process_message(provider_alice, protocol_commit_message)
        .expect("could not process message.");
    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
        processed_commit_message.into_content()
    {
        // Merge staged commit
        alice_group
            .merge_staged_commit(provider_alice, *staged_commit)
            .expect("Error merging staged commit.");
    }


    //charlie join the group using welcome
    let serialized_welcome_for_charlie = welcome_out_for_charlie.tls_serialize_detached().expect("error serializing");

    // bob can now de-serialize the message as an [`MlsMessageIn`] ...
    let mls_message_in_for_charlie = MlsMessageIn::tls_deserialize(&mut serialized_welcome_for_charlie.as_slice())
        .expect("An unexpected error occurred.");

    // ... and inspect the message.
    let welcome_of_charlie = match mls_message_in_for_charlie.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        // We know it's a welcome message, so we ignore all other cases.
        _ => unreachable!("Unexpected message type."),
    };

    //charlie now can join the group
    let group_config_join_charlie = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut charlie_group = StagedWelcome::new_from_welcome(
        provider_charlie,
        &group_config_join_charlie,
        welcome_of_charlie,
        None,
    )
        .expect("failed to create staged join [charlie]").into_group(provider_charlie)
        .expect("failed to create MLSGroup [charlie] by welcome");

    /*-------------Group Established for Charlie [Bob, and Alice too]--------------*/

    //bob create message:
    let bob_message = b"Hi Group. How are you all!. I added Charlie to our group...";
    let bob_mls_message_out = bob_group
        .create_message(provider_bob, &bob_signer, bob_message)
        .expect("error creating application message for group");

    //other group members access the message
    //Group serializes the message
    let serialized_group_application_message = bob_mls_message_out.to_bytes().expect("unable to serialize application message");
    let group_mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_group_application_message).expect("could not deserialize message.");

    let group_protocol_message: ProtocolMessage = group_mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");


    //alice process the message
    let processed_application_message_alice = alice_group
        .process_message(provider_alice, group_protocol_message.clone())
        .expect("could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_application_message_alice.into_content()
    {
        // Check the message
        assert_eq!(bytes_to_string(application_message.into_bytes()), "Hi Group. How are you all!. I added Charlie to our group...");
    } else {
        panic!("Not an application message")
    }


    //charlie process message
    let processed_application_message_charlie = charlie_group
        .process_message(provider_charlie, group_protocol_message.clone())
        .expect("could not process message.");
    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_application_message_charlie.into_content()
    {
        // Check the message
        assert_eq!(bytes_to_string(application_message.into_bytes()), "Hi Group. How are you all!. I added Charlie to our group...");
    } else {
        panic!("Not an application message")
    }
}

#[cfg(test)]
mod tests {
    use crate::{run_open_mls};
    #[test]
    fn open_mls_internal() {
        run_open_mls();
    }
    /* #[test]
     // already tested, no need to test the protocol
     fn open_mls_api() {
         const ALICE: &str = "Alice";
         const BOB: &str = "Bob";
         const ALICE_GROUP_ID: &str = "Alice_Group";

         //register Alice
         let alice_register_json_str = register_user(&ALICE);

         //register Bob
         let bob_register_json_str = register_user(&BOB);


         //Alice create group
         let created_group_by_alice = create_group(&ALICE_GROUP_ID, &alice_register_json_str);

         //Alice invite Bob to Alice_Group
         /*
         Use a helper to extract Bob's key package from Bob's Register JSON data. Because, ALice needs Bob's Key Package to invite.
         And assume Bob publish his key package to server, So alice can fetch it up.
         Alice invite Bob to group
          */
         let bob_key_package = get_bobs_key_package_as_json_string(&bob_register_json_str); //Assume this was retrieved from the server

         let alice_invited_bob_group_data = invite_member(&alice_register_json_str, &bob_key_package, &created_group_by_alice);

         //Bob crate new group from Alice's welcome message
         let serialized_welcome_message = get_serialized_welcome_message_out(&alice_invited_bob_group_data); // use the helper function to separate out the welcome message (delivered through DS)
         //Bob join the group and create his own
         let created_group_by_bob = create_group_from_welcome(&serialized_welcome_message);

         //Alice create an Application Message in the newly updated (Bob Added) Group
         let alice_updated_group = get_invite_updated_group(&alice_invited_bob_group_data);
         let serialized_application_message_out = create_application_message(&alice_register_json_str, &alice_updated_group, "Hi Bob!!");

         //Bob process the message in his group
         let processed_message = process_application_message(&created_group_by_bob, &serialized_application_message_out);

         assert_eq!(processed_message, "Hi Bob!!");
     }*/
}
