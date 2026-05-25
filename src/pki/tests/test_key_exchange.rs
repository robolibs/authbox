use super::*;

#[test]
fn key_exchange_envelope_serializes_validates_digest_and_roundtrips_sealed_boxes() {
    let empty_digest = key_exchange::blake2b_256(&[]);
    assert_eq!(
        empty_digest,
        [
            0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
            0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
            0xf1, 0x2f, 0xe3, 0xa8,
        ]
    );

    let envelope = key_exchange::Envelope {
        associated_data: b"context".to_vec(),
        ciphertext: vec![0xaa; key_exchange::SEALED_BOX_OVERHEAD_BYTES + 3],
    };
    let serialized = envelope.serialize();
    assert_eq!(serialized[0..4], key_exchange::MAGIC.to_le_bytes());
    assert_eq!(serialized[4], key_exchange::VERSION);
    let decoded = key_exchange::Envelope::deserialize(&serialized).unwrap();
    assert_eq!(decoded, envelope);

    let mut tampered = serialized;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(key_exchange::Envelope::deserialize(&tampered).is_err());

    let bad_key = key_exchange::create_envelope(b"payload", &[1, 2, 3]);
    assert!(!bad_key.success);
    assert_eq!(
        bad_key.error,
        "Recipient public key must be PUBLICKEYBYTES bytes"
    );

    let alice_secret: [u8; 32] =
        hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
    let alice_public = key_exchange::x25519_public_key(&alice_secret).unwrap();
    assert_eq!(
        alice_public.to_vec(),
        hex_bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );

    let ephemeral_secret: [u8; 32] =
        hex_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap();
    let sealed = key_exchange::create_envelope_with_ephemeral_secret(
        b"payload",
        &alice_public,
        b"context",
        &ephemeral_secret,
    );
    assert!(sealed.success, "{}", sealed.error);

    let mut recipient_private = alice_public.to_vec();
    recipient_private.extend(alice_secret);
    let (opened, aad) =
        key_exchange::consume_envelope_with_associated_data(&sealed.data, &recipient_private);
    assert!(opened.success, "{}", opened.error);
    assert_eq!(opened.data, b"payload");
    assert_eq!(aad, b"context");

    let mut tampered_sealed = sealed.data.clone();
    let last = tampered_sealed.len() - 1;
    tampered_sealed[last] ^= 0x80;
    let tampered_result = key_exchange::consume_envelope(&tampered_sealed, &recipient_private);
    assert!(!tampered_result.success);
    assert_eq!(tampered_result.error, "Invalid key exchange envelope");
}

#[test]
fn key_exchange_detail_namespace_exposes_cpp_envelope_surface() {
    assert_eq!(key_exchange::detail::MAGIC, key_exchange::MAGIC);
    assert_eq!(key_exchange::detail::VERSION, key_exchange::VERSION);
    assert_eq!(key_exchange::detail::DIGEST_SIZE, key_exchange::DIGEST_SIZE);

    let mut encoded = Vec::new();
    key_exchange::detail::append_u32(&mut encoded, 0x4c4b_5847);
    assert_eq!(encoded, vec![0x47, 0x58, 0x4b, 0x4c]);
    assert_eq!(key_exchange::detail::read_u32(&encoded), 0x4c4b_5847);

    let envelope = key_exchange::detail::Envelope {
        associated_data: b"detail-context".to_vec(),
        ciphertext: vec![0x5a; key_exchange::SEALED_BOX_OVERHEAD_BYTES],
    };
    let decoded = key_exchange::detail::Envelope::deserialize(&envelope.serialize()).unwrap();
    assert_eq!(decoded.associated_data, b"detail-context");
    assert_eq!(
        decoded.ciphertext,
        vec![0x5a; key_exchange::SEALED_BOX_OVERHEAD_BYTES]
    );
}

#[test]
fn key_exchange_memory_and_file_result_surfaces_match_cpp_shape() {
    let recipient_secret: [u8; 32] =
        hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
    let recipient_public = key_exchange::x25519_public_key(&recipient_secret).unwrap();
    let mut recipient_private = recipient_public.to_vec();
    recipient_private.extend(recipient_secret);

    let default_env = key_exchange::create_envelope(b"payload", &recipient_public);
    assert!(default_env.success, "{}", default_env.error);
    let (default_opened, default_aad) =
        key_exchange::consume_envelope_with_associated_data(&default_env.data, &recipient_private);
    assert!(default_opened.success, "{}", default_opened.error);
    assert_eq!(default_opened.data, b"payload");
    assert!(default_aad.is_empty());

    let mut default_memory = vec![0u8; 512];
    let mut default_written = usize::MAX;
    let default_write = key_exchange::write_envelope_to_memory(
        &mut default_memory,
        &mut default_written,
        b"payload",
        &recipient_public,
    );
    assert!(default_write.success, "{}", default_write.error);
    assert!(default_written > 0);
    let (default_memory_opened, default_memory_aad) =
        key_exchange::consume_envelope_with_associated_data(
            &default_memory[..default_written],
            &recipient_private,
        );
    assert!(
        default_memory_opened.success,
        "{}",
        default_memory_opened.error
    );
    assert_eq!(default_memory_opened.data, b"payload");
    assert!(default_memory_aad.is_empty());

    let mut too_small = [0u8; 8];
    let (small_result, written) =
        key_exchange::write_envelope_to_memory_result_with_associated_data(
            &mut too_small,
            b"payload",
            &recipient_public,
            b"context",
        );
    assert!(!small_result.success);
    assert_eq!(
        small_result.error,
        "Shared memory region too small for envelope"
    );
    assert_eq!(written, 0);

    let mut memory = vec![0u8; 512];
    let (write_result, written) =
        key_exchange::write_envelope_to_memory_result_with_associated_data(
            &mut memory,
            b"payload",
            &recipient_public,
            b"context",
        );
    assert!(write_result.success, "{}", write_result.error);
    assert!(written > 0);

    let (opened, aad) =
        key_exchange::consume_envelope_with_associated_data(&memory[..written], &recipient_private);
    assert!(opened.success, "{}", opened.error);
    assert_eq!(opened.data, b"payload");
    assert_eq!(aad, b"context");

    let missing = key_exchange::read_envelope_from_file(
        "/nonexistent/authbox-key-exchange-envelope.bin",
        &recipient_private,
    );
    assert!(!missing.success);
    assert_eq!(missing.error, "Unable to open envelope file for reading");
}

#[test]
fn key_exchange_consume_invalid_envelope_errors_match_cpp_surface() {
    let recipient_secret: [u8; 32] =
        hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
    let recipient_public = key_exchange::x25519_public_key(&recipient_secret).unwrap();
    let mut recipient_private = recipient_public.to_vec();
    recipient_private.extend(recipient_secret);

    let empty = key_exchange::consume_envelope(&[], &recipient_private);
    assert!(!empty.success);
    assert_eq!(empty.error, "Invalid envelope buffer");

    let wrong_magic = vec![0u8; 4 + 1 + 1 + 2 + 4 + 4 + key_exchange::DIGEST_SIZE];
    let bad = key_exchange::consume_envelope(&wrong_magic, &recipient_private);
    assert!(!bad.success);
    assert_eq!(bad.error, "Invalid key exchange envelope");

    let mut aad = b"previous".to_vec();
    let bad_with_out = key_exchange::consume_envelope_with_associated_data_out(
        &wrong_magic,
        &recipient_private,
        Some(&mut aad),
    );
    assert!(!bad_with_out.success);
    assert_eq!(bad_with_out.error, "Invalid key exchange envelope");
    assert_eq!(aad, b"previous");
}

#[test]
fn key_exchange_associated_data_is_only_returned_after_success_like_cpp_out_param() {
    let recipient_secret: [u8; 32] =
        hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
    let recipient_public = key_exchange::x25519_public_key(&recipient_secret).unwrap();
    let mut recipient_private = recipient_public.to_vec();
    recipient_private.extend(recipient_secret);
    let ephemeral_secret: [u8; 32] =
        hex_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap();

    let sealed = key_exchange::create_envelope_with_ephemeral_secret(
        b"payload",
        &recipient_public,
        b"context",
        &ephemeral_secret,
    );
    assert!(sealed.success, "{}", sealed.error);

    let (bad_key_result, bad_key_aad) =
        key_exchange::consume_envelope_with_associated_data(&sealed.data, &[0u8; 32]);
    assert!(!bad_key_result.success);
    assert_eq!(
        bad_key_result.error,
        "Recipient private key must contain public and secret material"
    );
    assert!(bad_key_aad.is_empty());

    let mut tampered_private = recipient_private.clone();
    tampered_private[40] ^= 0x80;
    let (decrypt_result, decrypt_aad) =
        key_exchange::consume_envelope_with_associated_data(&sealed.data, &tampered_private);
    assert!(!decrypt_result.success);
    assert!(decrypt_aad.is_empty());

    let (opened, aad) =
        key_exchange::consume_envelope_with_associated_data(&sealed.data, &recipient_private);
    assert!(opened.success, "{}", opened.error);
    assert_eq!(opened.data, b"payload");
    assert_eq!(aad, b"context");
}

#[test]
fn key_exchange_cpp_style_out_parameter_helpers_return_associated_data() {
    let recipient_secret: [u8; 32] =
        hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .try_into()
            .unwrap();
    let recipient_public = key_exchange::x25519_public_key(&recipient_secret).unwrap();
    let mut recipient_private = recipient_public.to_vec();
    recipient_private.extend(recipient_secret);
    let ephemeral_secret: [u8; 32] =
        hex_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
            .try_into()
            .unwrap();

    let sealed = key_exchange::create_envelope_with_ephemeral_secret(
        b"payload",
        &recipient_public,
        b"context",
        &ephemeral_secret,
    );
    assert!(sealed.success, "{}", sealed.error);

    let mut aad = Vec::new();
    let opened = key_exchange::consume_envelope_with_associated_data_out(
        &sealed.data,
        &recipient_private,
        Some(&mut aad),
    );
    assert!(opened.success, "{}", opened.error);
    assert_eq!(opened.data, b"payload");
    assert_eq!(aad, b"context");

    let mut memory = vec![0u8; 512];
    let mut written = usize::MAX;
    let write = key_exchange::write_envelope_to_memory_with_written(
        &mut memory,
        &mut written,
        b"payload",
        &recipient_public,
        b"context",
    );
    assert!(write.success, "{}", write.error);
    assert!(written > 0);
    assert_eq!(write.data, Vec::<u8>::new());

    let mut memory_aad = Vec::new();
    let memory_opened = key_exchange::read_envelope_from_memory_with_associated_data_out(
        &memory[..written],
        &recipient_private,
        Some(&mut memory_aad),
    );
    assert!(memory_opened.success, "{}", memory_opened.error);
    assert_eq!(memory_opened.data, b"payload");
    assert_eq!(memory_aad, b"context");

    let mut too_small = [0u8; 8];
    written = usize::MAX;
    let small = key_exchange::write_envelope_to_memory_with_written(
        &mut too_small,
        &mut written,
        b"payload",
        &recipient_public,
        b"context",
    );
    assert!(!small.success);
    assert_eq!(written, 0);
    assert_eq!(small.error, "Shared memory region too small for envelope");
}
