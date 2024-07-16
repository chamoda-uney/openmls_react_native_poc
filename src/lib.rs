use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls::prelude::tls_codec::*;


#[no_mangle]
pub extern "C" fn run_open_mls() {
    // Define ciphersuite ...
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    // ... and the crypto backend to use.
    let backend = &OpenMlsRustCrypto::default();


    // Alice credential
    let (alice_credential_with_key,
        alice_signer) = generate_credential(
        "Alice".into(),
        ciphersuite,
        backend,
    );

    // Bob credential
    let (bob_credential_with_key,
        bob_signer) = generate_credential(
        "Bob".into(),
        ciphersuite,
        backend,
    );

    //alice key package bundle
    //let alice_key_package_bundle = generate_key_package(ciphersuite, backend, &alice_signer, alice_credential_with_key);

    //bob key package bundle
    let bob_key_package_bundle = generate_key_package(ciphersuite,
                                                      backend,
                                                      &bob_signer,
                                                      bob_credential_with_key);


    //alice create the group
    //bob now can join the group
    let group_config_create = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice_group = MlsGroup::new(backend, &alice_signer,
                                        &group_config_create,
                                        alice_credential_with_key).expect("unexpected error occurred in creating group");

    //alice invites bob
    let bob_key_package = bob_key_package_bundle.key_package().clone();
    let (_mls_message_out, welcome_out, _) = alice_group.add_members(backend,
                                                                     &alice_signer,
                                                                     &[bob_key_package]).expect("Error adding member to group");

    //merge pending commit
    alice_group.merge_pending_commit(backend).expect("error merging pending commit");

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
        backend,
        &group_config_join,
        welcome,
        None,
    )
        .expect("failed to create staged join").into_group(backend)
        .expect("failed to create MLSGroup by welcome");


    /*-------------Group Established--------------*/

    //alice create message:
    let alice_message = b"Hi Bob. How are you!. I'm Alice...";
    let mls_message_out = alice_group
        .create_message(backend, &alice_signer, alice_message)
        .expect("error creating application message for bob");


    //Bob process the message
    let serialized_application_message = mls_message_out.to_bytes().expect("unable to serialize application message");
    let mls_message_in =
        MlsMessageIn::tls_deserialize_exact(serialized_application_message).expect("could not deserialize message.");

    let protocol_message: ProtocolMessage = mls_message_in.try_into_protocol_message().expect("unable to convert to protocol message.");
    let processed_message = bob_group
        .process_message(backend, protocol_message)
        .expect("could not process message.");

    if let ProcessedMessageContent::ApplicationMessage(application_message) =
        processed_message.into_content()
    {
        // Check the message
        bytes_to_string(application_message.into_bytes());
    }
}


fn generate_credential(name: &str, ciphersuite: Ciphersuite,
                       backend: &impl OpenMlsProvider) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = Credential::new(CredentialType::Basic, name.into());
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


fn generate_key_package(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
) -> KeyPackageBundle {
    let kp = KeyPackage::builder().build(ciphersuite, backend, signer, credential_with_key).unwrap();
    return kp;
}

fn bytes_to_string(bytes: Vec<u8>) -> String {
    let vec_to_string = String::from_utf8(bytes).unwrap();
    println!("bob receiving message from alice: {}", vec_to_string);
    return vec_to_string.to_string();
}

/*#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = run_open_mls();
        assert_eq!(result, 4);
    }
}*/
