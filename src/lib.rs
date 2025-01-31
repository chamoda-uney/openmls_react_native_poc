mod helpers;
mod structs;
mod openmls_rust_persistent_crypto;

uniffi::setup_scaffolding!();

use std::{fs, io};
use openmls::prelude::*;
use openmls::prelude::tls_codec::*;
use openmls_traits::storage::StorageProvider;
use serde_json;
use serde_json::{from_str, to_string};
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

7. Process Protocol Message (Commit Message)
    - commit the staged commit to the MLS group
    - return the group as json
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

    signer.store(provider.storage()).unwrap();

    let registered_user_data = RegisteredUserData {
        key_package,
        signer,
        credential_with_key,
    };

    let serialized = to_string(&registered_user_data).expect("unable to convert RegisteredUserData to string");

    provider.save_keystore(); //saving the keystore for future use (note, this is expiring in 3 months)
    return serialized;
}

#[uniffi::export]
fn mls_create_keypackage(registered_user_data_json_str: &str) -> String {
    let provider = get_provider();
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");

    let key_package_bundle = generate_key_package(CIPHERSUITE,
                                                  &provider,
                                                  &registered_user_data.signer,
                                                  registered_user_data.credential_with_key.clone());
    let key_package = key_package_bundle.key_package().clone();
    let serialized = to_string(&key_package).expect("unable to convert KeyPackage to string");
    provider.save_keystore();
    return serialized;
}
#[uniffi::export]
fn mls_create_group(group_id: &str, registered_user_data_json_str: &str) {
    let provider = get_provider();
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");

    let group_config_create = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    MlsGroup::new_with_group_id(&provider, &registered_user_data.signer,
                                &group_config_create,
                                GroupId::from_slice(group_id.as_bytes()),
                                registered_user_data.credential_with_key).expect("unexpected error occurred in creating group");
    provider.save_keystore();

    //let serialized = to_string(&mls_group).expect("unable to convert MLSGroup to string");
    // return serialized;
}

#[uniffi::export]
fn mls_invite_member(registered_user_data_json_str: &str, member_key_package_json_str: &str, group_id: &str) -> String {
    let provider = get_provider();
    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");
    let member_key_package: KeyPackage = from_str(&member_key_package_json_str).expect("unable to convert string to KeyPackage");
    let mut mls_group: MlsGroup = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id.as_bytes())).unwrap().expect("unable to load group");


    let (mls_message_out, welcome_out, _) = mls_group.add_members(&provider,
                                                                  &registered_user_data.signer,
                                                                  &[member_key_package]).expect("Error adding member to group");

    //merge pending commit
    mls_group.merge_pending_commit(&provider).expect("error merging pending commit");

    let invited_member_data = InvitedMemberData {
        serialized_welcome_out: welcome_out.tls_serialize_detached().expect("error serializing welcome_out"),
        serialized_mls_message_out: mls_message_out.tls_serialize_detached().expect("error serializing mls_message_out"),
    };
    let serialized = to_string(&invited_member_data).expect("unable to convert InvitedMemberData to string");
    provider.save_keystore();
    return serialized;
}

#[uniffi::export]
fn mls_create_group_from_welcome(serialized_welcome_message_json_str: &str) {
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
    let mut mls_group = StagedWelcome::new_from_welcome(
        &provider,
        &group_config_join,
        welcome,
        None,
    )
        .expect("failed to create staged join").into_group(&provider)
        .expect("failed to create MLSGroup by welcome");

    //merge pending commit
    mls_group.merge_pending_commit(&provider).expect("error merging pending commit");

    provider.save_keystore();
}

#[uniffi::export]
fn mls_create_application_message(registered_user_data_json_str: &str, message: &str, group_id: &str) -> String {
    let provider = get_provider();

    let registered_user_data: RegisteredUserData = from_str(&registered_user_data_json_str).expect("unable to convert string to RegisteredUserData");
    let mut mls_group: MlsGroup = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id.as_bytes())).unwrap().expect("unable to load group");

    let mls_message_out = mls_group
        .create_message(&provider, &registered_user_data.signer, message.as_bytes())
        .expect("error creating application message");

    let serialized = to_string(&mls_message_out.tls_serialize_detached().expect("unable to serialize application message")).expect("unable to convert application MLSMessageOut Vec<u8> to string");
    return serialized;
}
#[uniffi::export]
fn mls_process_application_message(group_id: &str, serialized_application_message_json_str: &str) -> String {
    let provider = get_provider();

    let serialized_application_message: Vec<u8> = from_str(serialized_application_message_json_str).expect("unable to convert serialized_application_message Vec<u8> to string");
    let mut mls_group: MlsGroup = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id.as_bytes())).unwrap().expect("unable to load group");


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
fn mls_process_commit_message(group_id: &str, serialized_commit_message_json_str: &str) {
    let provider = get_provider();

    let serialized_commit_message: Vec<u8> = from_str(serialized_commit_message_json_str).expect("unable to convert serialized_commit_message Vec<u8> to string");
    let mut mls_group: MlsGroup = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id.as_bytes())).unwrap().expect("unable to load group");


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
        mls_group.merge_pending_commit(&provider).expect("error merging pending commit");
        provider.save_keystore();
    } else {
        panic!("Not an commit message")
    }
}

#[uniffi::export]
fn mls_get_group_members(group_id: &str) -> String {
    let provider = get_provider();

    let mls_group: MlsGroup = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id.as_bytes())).unwrap().expect("unable to load group");

    let mut members: Vec<String> = Vec::new();

    for i in mls_group.members().into_iter() {
        members.push(bytes_to_string(i.credential.serialized_content().to_vec()));
    };

    return to_string(&members).expect("unable to convert Vec<String> to string");
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
                                        alice_credential_with_key.clone()).expect("unexpected error occurred in creating group");


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
    let serialized_application_message = mls_message_out.tls_serialize_detached().expect("unable to serialize application message");
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
    let serialized_commit_message = mls_message_out_for_other_group_members.tls_serialize_detached().expect("unable to serialize commit message");
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
    let serialized_group_application_message = bob_mls_message_out.tls_serialize_detached().expect("unable to serialize application message");
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

fn run_exported_functions() {
    struct Client {
        file_path: String,
        name: String,
        registered_user_data: String,
        key_package: String,
    }

    impl Client {
        pub fn extract_key_package(&mut self) {
            let rud: RegisteredUserData = from_str(&self.registered_user_data).expect("unable to deserialize RegisteredUserData");
            self.key_package = to_string(&rud.key_package).expect("unable to serialize KeyPackage");
        }
    }

    let mut alice = Client {
        file_path: "target/alice.json".to_string(),
        name: "Alice".to_string(),
        registered_user_data: "".to_string(),
        key_package: "".to_string(),
    };

    let mut bob = Client {
        file_path: "target/bob.json".to_string(),
        name: "Bob".to_string(),
        registered_user_data: "".to_string(),
        key_package: "".to_string(),
    };

    let mut charlie = Client {
        file_path: "target/charlie.json".to_string(),
        name: "Charlie".to_string(),
        registered_user_data: "".to_string(),
        key_package: "".to_string(),
    };

    //delete the previous storage files (to simulate new client at first)
    fs::remove_file(alice.file_path.clone()).ok();
    fs::remove_file(bob.file_path.clone()).ok();
    fs::remove_file(charlie.file_path.clone()).ok();

    let group_id = "hello";

    //register 3 users (this will create files in target/alice.json, target/bob.json and target/charlie.json)
    mls_init(alice.file_path.clone());
    alice.registered_user_data = mls_register_user(alice.name.as_str());
    alice.extract_key_package();

    mls_init(bob.file_path.clone());
    bob.registered_user_data = mls_register_user(bob.name.as_str());
    bob.extract_key_package();

    mls_init(charlie.file_path.clone());
    charlie.registered_user_data = mls_register_user(bob.name.as_str());
    charlie.extract_key_package();


    //---ALICE---
    mls_init(alice.file_path.clone());
    //alice create group
    mls_create_group(&group_id, alice.registered_user_data.as_str());

    //alice invite bob
    let alice_invited_bob_data: InvitedMemberData = from_str(&mls_invite_member(&*alice.registered_user_data, &*bob.key_package, &group_id)).unwrap();


    //---BOB---
    mls_init(bob.file_path.clone());
    //now bob, imaging bob get json messages (serialized welcome out from delivery service), and process it to create a group from welcome
    let bobs_welcome_message_received_from_ds = to_string(&alice_invited_bob_data.serialized_welcome_out).unwrap();
    mls_create_group_from_welcome(bobs_welcome_message_received_from_ds.as_str());
    bob.key_package = mls_create_keypackage(&bob.registered_user_data);

    //Now Alice and Bob are in Group. Let's send a message to Bob from Alice.

    //---ALICE---
    mls_init(alice.file_path.clone());
    let serialized_application_message_for_bob = mls_create_application_message(alice.registered_user_data.as_str(), "hi bob", &group_id);


    //---BOB---
    mls_init(bob.file_path.clone());
    //bob received the serialized application message from DS, (JSON format)
    let bobs_message = mls_process_application_message(&group_id, serialized_application_message_for_bob.as_str());
    assert_eq!(bobs_message, "hi bob");


    //now let's invite charlie to the group. (bob invite charlie)
    mls_init(bob.file_path.clone());
    let bob_invited_charlie_data: InvitedMemberData = from_str(&mls_invite_member(&*bob.registered_user_data, &*charlie.key_package, &group_id)).unwrap();

    //--CHARLIE--
    mls_init(charlie.file_path.clone());
    //now charlie, imaging charlie get json messages (serialized welcome out from delivery service), and process it to create a group from welcome
    let charlies_welcome_message_received_from_ds = to_string(&bob_invited_charlie_data.serialized_welcome_out).unwrap();
    mls_create_group_from_welcome(charlies_welcome_message_received_from_ds.as_str());
    charlie.key_package = mls_create_keypackage(&charlie.registered_user_data);


    //--ALICE---
    //now alice have to process the commit message of adding charlie to the group
    mls_init(alice.file_path.clone());
    let alices_commit_message_received_from_ds = to_string(&bob_invited_charlie_data.serialized_mls_message_out).unwrap();
    mls_process_commit_message(&group_id, alices_commit_message_received_from_ds.as_str());

    //--CHARLIE---
    //now charlie create a message for entire group (alice & bob)
    mls_init(charlie.file_path.clone());
    let serialized_application_message_for_group = mls_create_application_message(charlie.registered_user_data.as_str(), "Hi group!. I'm charlie", &group_id);

    //--ALICE---
    //now alice consume the message
    mls_init(alice.file_path.clone());
    //alice received the serialized application message from DS, (JSON format)
    assert_eq!(mls_process_application_message(&group_id, serialized_application_message_for_group.as_str()), "Hi group!. I'm charlie");

    //--BOB---
    //now bob consume the message
    mls_init(bob.file_path.clone());
    //bob received the serialized application message from DS, (JSON format)
    assert_eq!(mls_process_application_message(&group_id, serialized_application_message_for_group.as_str()), "Hi group!. I'm charlie");

    // ---creating second group---
    let group_id_2 = "hello_2";
    //---ALICE---
    mls_init(alice.file_path.clone());
    //alice create group
    mls_create_group(&group_id_2, alice.registered_user_data.as_str());
    //alice invite bob
    mls_init(alice.file_path.clone());
    let alice_invited_bob_data_group_id_2: InvitedMemberData = from_str(&mls_invite_member(&*alice.registered_user_data, &*bob.key_package, &group_id_2)).unwrap();


    //---BOB---
    mls_init(bob.file_path.clone());
    //now bob, imaging bob get json messages (serialized welcome out from delivery service), and process it to create a group from welcome
    let bobs_welcome_message_received_from_ds_group_id_2 = to_string(&alice_invited_bob_data_group_id_2.serialized_welcome_out).unwrap();
    mls_create_group_from_welcome(bobs_welcome_message_received_from_ds_group_id_2.as_str());
    bob.key_package = mls_create_keypackage(&bob.registered_user_data);

    //now bob invite charlie also
    let bob_invited_charlie_data_group_id_2: InvitedMemberData = from_str(&mls_invite_member(&*bob.registered_user_data, &*charlie.key_package, &group_id_2)).unwrap();

    //--CHARLIE--
    //now charlie join the group
    mls_init(charlie.file_path.clone());
    let charlies_welcome_message_received_from_ds_group_id_2 = to_string(&bob_invited_charlie_data_group_id_2.serialized_welcome_out).unwrap();
    mls_create_group_from_welcome(charlies_welcome_message_received_from_ds_group_id_2.as_str());
    charlie.key_package = mls_create_keypackage(&charlie.registered_user_data);

    //--ALICE--
    //now alice has to process the commit message sent by charlie
    mls_init(alice.file_path.clone());
    let charlie_added_commit_received_from_ds_group_id_2 = to_string(&bob_invited_charlie_data_group_id_2.serialized_mls_message_out).unwrap();
    mls_process_commit_message(&group_id_2, charlie_added_commit_received_from_ds_group_id_2.as_str());


    //now all are in group 3, Bob send a message to group 3
    mls_init(bob.file_path.clone());
    let serialized_application_message_for_group_id_2 = mls_create_application_message(bob.registered_user_data.as_str(), "Hi group 2!. What's up", &group_id_2);

    //--ALICE---
    //now alice consume the message
    mls_init(alice.file_path.clone());
    //alice received the serialized application message from DS, (JSON format)
    assert_eq!(mls_process_application_message(&group_id_2, serialized_application_message_for_group_id_2.as_str()), "Hi group 2!. What's up");

    //--CHARLIE---
    //now charlie consume the message
    mls_init(charlie.file_path.clone());
    //alice received the serialized application message from DS, (JSON format)
    assert_eq!(mls_process_application_message(&group_id_2, serialized_application_message_for_group_id_2.as_str()), "Hi group 2!. What's up");


    //let's send messages to first group they created
    //now all are in group 3, Bob send a message to group 3
    mls_init(bob.file_path.clone());
    let serialized_application_message_for_group_id_1 = mls_create_application_message(bob.registered_user_data.as_str(), "Hi group 1!. What's up", &group_id);

    //--ALICE---
    //now alice consume the message
    mls_init(alice.file_path.clone());
    //alice received the serialized application message from DS, (JSON format)
    assert_eq!(mls_process_application_message(&group_id, serialized_application_message_for_group_id_1.as_str()), "Hi group 1!. What's up");

    //--CHARLIE---
    //now charlie consume the message
    mls_init(charlie.file_path.clone());
    //alice received the serialized application message from DS, (JSON format)
    assert_eq!(mls_process_application_message(&group_id, serialized_application_message_for_group_id_1.as_str()), "Hi group 1!. What's up");
}

#[cfg(test)]
mod tests {
    use crate::{run_exported_functions, run_open_mls};
    #[test]
    fn open_mls_internal() {
        run_open_mls();
    }
    #[test]
    fn run_open_mls_api() {
        run_exported_functions();
    }
}
