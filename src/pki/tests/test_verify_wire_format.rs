use super::*;

#[test]
fn verify_wire_format_serializes_and_deserializes_verify_request() {
    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: vec![0x30, 0x01, 0x00],
        }],
        validation_timestamp: 123_456_789,
        flags: RequestFlags::IncludeResponderCert,
        nonce: vec![0xab; 32],
    };

    let encoded = serialize(&request);
    assert_eq!(&encoded[0..4], &MAGIC);
    assert_eq!(encoded[4], VERSION);
    assert_eq!(encoded[5], MessageType::VerifyRequest as u8);

    let decoded: VerifyRequest = deserialize(&encoded).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn verify_wire_format_roundtrips_requests_responses_and_health_from_central_port() {
    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: vec![1, 2, 3],
        }],
        validation_timestamp: 123,
        flags: RequestFlags::IncludeResponderCert,
        nonce: vec![9; 32],
    };
    let encoded = serialize(&request);
    assert_eq!(&encoded[0..4], &MAGIC);
    assert_eq!(encoded[4], VERSION);
    assert_eq!(encoded[5], MessageType::VerifyRequest as u8);
    let decoded: VerifyRequest = deserialize(&encoded).unwrap();
    assert_eq!(decoded, request);

    let response = VerifyResponse {
        status: VerifyStatus::Good,
        reason: "Certificate is valid".to_string(),
        revocation_time: 0,
        this_update: 123,
        next_update: 456,
        signature: vec![7; 64],
        nonce: vec![9; 32],
        responder_cert_der: vec![4, 5, 6],
    };
    let decoded_response: VerifyResponse = deserialize(&serialize(&response)).unwrap();
    assert_eq!(decoded_response, response);

    let health: HealthCheckResponse = deserialize(&serialize(&HealthCheckResponse {
        status: ServingStatus::Serving,
    }))
    .unwrap();
    assert_eq!(health.status, ServingStatus::Serving);

    let mut bad_magic = encoded;
    bad_magic[0] = 0;
    assert!(deserialize::<VerifyRequest>(&bad_magic).is_err());
}

#[test]
fn verify_wire_format_generates_empty_request_nonce_for_wire_payloads() {
    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: vec![0x30, 0x01, 0x00],
        }],
        ..VerifyRequest::default()
    };

    let decoded: VerifyRequest = deserialize(&serialize(&request)).unwrap();

    assert_eq!(decoded.nonce.len(), 32);
    #[cfg(unix)]
    assert_ne!(decoded.nonce, vec![0; 32]);

    let decoded_again: VerifyRequest = deserialize(&serialize(&request)).unwrap();
    assert_eq!(decoded_again.nonce.len(), 32);
    #[cfg(unix)]
    assert_ne!(decoded_again.nonce, decoded.nonce);
}

#[test]
fn verify_wire_format_serializes_multiple_certificates_in_chain() {
    let request = VerifyRequest {
        certificate_chain: vec![
            CertificateData {
                der_bytes: vec![1, 2, 3],
            },
            CertificateData {
                der_bytes: vec![4, 5, 6, 7],
            },
        ],
        nonce: vec![0xcd; 32],
        ..VerifyRequest::default()
    };

    let decoded: VerifyRequest = deserialize(&serialize(&request)).unwrap();

    assert_eq!(decoded.certificate_chain.len(), 2);
    assert_eq!(decoded.certificate_chain[0].der_bytes, vec![1, 2, 3]);
    assert_eq!(decoded.certificate_chain[1].der_bytes, vec![4, 5, 6, 7]);
}

#[test]
fn verify_wire_format_serializes_and_deserializes_verify_response() {
    let response = VerifyResponse {
        status: VerifyStatus::Good,
        reason: "Certificate is valid".to_string(),
        revocation_time: 0,
        this_update: 111,
        next_update: 222,
        signature: vec![0x11; 64],
        nonce: vec![0x22; 32],
        responder_cert_der: vec![0x30, 0x03, 0x02, 0x01, 0x01],
    };

    let encoded = serialize(&response);
    assert_eq!(&encoded[0..4], &MAGIC);
    assert_eq!(encoded[4], VERSION);
    assert_eq!(encoded[5], MessageType::VerifyResponse as u8);

    let decoded: VerifyResponse = deserialize(&encoded).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn verify_wire_format_serializes_health_messages() {
    let request = serialize(&HealthCheckRequest);
    assert_eq!(request.len(), 6);
    assert_eq!(&request[0..4], &MAGIC);
    assert_eq!(request[4], VERSION);
    assert_eq!(request[5], MessageType::HealthCheck as u8);
    let _: HealthCheckRequest = deserialize(&request).unwrap();

    let response = serialize(&HealthCheckResponse {
        status: ServingStatus::Serving,
    });
    assert_eq!(response.len(), 7);
    assert_eq!(&response[0..4], &MAGIC);
    assert_eq!(response[4], VERSION);
    assert_eq!(response[5], MessageType::HealthResponse as u8);
    let decoded: HealthCheckResponse = deserialize(&response).unwrap();
    assert_eq!(decoded.status, ServingStatus::Serving);
}

#[test]
fn verify_wire_format_rejects_bad_magic_and_version() {
    let request = VerifyRequest {
        nonce: vec![0x42; 32],
        ..VerifyRequest::default()
    };
    let encoded = serialize(&request);

    let mut bad_magic = encoded.clone();
    bad_magic[0] = 0;
    assert!(deserialize::<VerifyRequest>(&bad_magic).is_err());

    let mut bad_version = encoded.clone();
    bad_version[4] = VERSION.wrapping_add(1);
    assert!(deserialize::<VerifyRequest>(&bad_version).is_err());

    let mut trailing = encoded;
    trailing.extend([0xde, 0xad, 0xbe, 0xef]);
    let decoded: VerifyRequest = deserialize(&trailing).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn verify_wire_format_request_flags_support_cpp_style_bit_ops() {
    let flags = RequestFlags::None | RequestFlags::IncludeResponderCert;
    assert!(flags.contains(RequestFlags::IncludeResponderCert));
    assert_eq!(
        flags & RequestFlags::IncludeResponderCert,
        RequestFlags::IncludeResponderCert
    );
    assert_eq!(flags & RequestFlags::None, RequestFlags::None);

    let unknown = RequestFlags::from_bits(0x81);
    assert_eq!(unknown.bits(), 0x81);
    assert!(unknown.contains(RequestFlags::IncludeResponderCert));

    let request = VerifyRequest {
        flags: unknown,
        nonce: vec![0x99; 32],
        ..VerifyRequest::default()
    };
    let decoded: VerifyRequest = deserialize(&serialize(&request)).unwrap();
    assert_eq!(decoded.flags.bits(), 0x81);
}

#[test]
fn verify_wire_format_serializer_facade_matches_cpp_static_helper_shape() {
    let mut buffer = Vec::new();
    Serializer::write_uint8(&mut buffer, 0x12);
    Serializer::write_uint16(&mut buffer, 0x3456);
    Serializer::write_uint32(&mut buffer, 0x789a_bcde);
    Serializer::write_uint64(&mut buffer, 0x0102_0304_0506_0708);
    Serializer::write_string(&mut buffer, "ok");
    Serializer::write_len_prefixed_bytes(&mut buffer, &[9, 8, 7]);
    Serializer::write_timestamp(&mut buffer, 0x1112_1314_1516_1718);

    let mut pos = 0;
    assert_eq!(Serializer::read_uint8(&buffer, &mut pos).unwrap(), 0x12);
    assert_eq!(Serializer::read_uint16(&buffer, &mut pos).unwrap(), 0x3456);
    assert_eq!(
        Serializer::read_uint32(&buffer, &mut pos).unwrap(),
        0x789a_bcde
    );
    assert_eq!(
        Serializer::read_uint64(&buffer, &mut pos).unwrap(),
        0x0102_0304_0506_0708
    );
    let string_len = Serializer::read_uint16(&buffer, &mut pos).unwrap() as usize;
    assert_eq!(
        Serializer::read_string(&buffer, &mut pos, string_len).unwrap(),
        "ok"
    );
    assert_eq!(
        Serializer::read_len_prefixed_bytes(&buffer, &mut pos).unwrap(),
        vec![9, 8, 7]
    );
    assert_eq!(
        Serializer::read_timestamp(&buffer, &mut pos).unwrap(),
        0x1112_1314_1516_1718
    );
    assert_eq!(pos, buffer.len());

    let request = VerifyRequest {
        nonce: vec![0x44; 32],
        ..VerifyRequest::default()
    };
    let encoded = Serializer::serialize(&request);
    assert_eq!(
        Serializer::validate_header(&encoded, MessageType::VerifyRequest).unwrap(),
        6
    );
    assert_eq!(
        Serializer::deserialize::<VerifyRequest>(&encoded).unwrap(),
        request
    );
}

#[test]
fn verify_wire_format_cpp_style_aliases_and_bool_deserialize_helpers_work() {
    assert_eq!(MessageType::VERIFY_REQUEST, MessageType::VerifyRequest);
    assert_eq!(MessageType::VERIFY_RESPONSE, MessageType::VerifyResponse);
    assert_eq!(MessageType::BATCH_REQUEST, MessageType::BatchRequest);
    assert_eq!(MessageType::BATCH_RESPONSE, MessageType::BatchResponse);
    assert_eq!(MessageType::HEALTH_CHECK, MessageType::HealthCheck);
    assert_eq!(MessageType::HEALTH_RESPONSE, MessageType::HealthResponse);
    assert_eq!(VerifyStatus::GOOD, VerifyStatus::Good);
    assert_eq!(VerifyStatus::REVOKED, VerifyStatus::Revoked);
    assert_eq!(VerifyStatus::UNKNOWN, VerifyStatus::Unknown);
    assert_eq!(RequestFlags::NONE, RequestFlags::None);
    assert_eq!(
        RequestFlags::INCLUDE_RESPONDER_CERT,
        RequestFlags::IncludeResponderCert
    );
    assert_eq!(ServingStatus::SERVING, ServingStatus::Serving);
    assert_eq!(ServingStatus::NOT_SERVING, ServingStatus::NotServing);
    assert_eq!(ServingStatus::UNKNOWN, ServingStatus::Unknown);

    let request = VerifyRequest::new(
        vec![CertificateData {
            der_bytes: vec![0x30, 0x01, 0x00],
        }],
        42,
        RequestFlags::INCLUDE_RESPONDER_CERT,
    );
    assert_eq!(request.nonce.len(), 32);

    let encoded = Serializer::serialize_verify_request(&request);
    let mut out = VerifyRequest::default();
    assert!(Serializer::deserialize_verify_request(&encoded, &mut out));
    assert_eq!(out, request);

    let batch = BatchVerifyRequest::new(vec![request.clone()]);
    let encoded_batch = Serializer::serialize_batch_verify_request(&batch);
    let mut out_batch = BatchVerifyRequest::default();
    assert!(Serializer::deserialize_batch_verify_request(
        &encoded_batch,
        &mut out_batch
    ));
    assert_eq!(out_batch, batch);

    let response = VerifyResponse {
        status: VerifyStatus::GOOD,
        reason: "ok".to_string(),
        nonce: vec![0x55; 32],
        ..VerifyResponse::default()
    };
    let encoded_response = Serializer::serialize_verify_response(&response);
    let mut out_response = VerifyResponse::default();
    assert!(Serializer::deserialize_verify_response(
        &encoded_response,
        &mut out_response
    ));
    assert_eq!(out_response, response);

    let batch_response = BatchVerifyResponse::new(vec![response]);
    let encoded_batch_response = Serializer::serialize_batch_verify_response(&batch_response);
    let mut out_batch_response = BatchVerifyResponse::default();
    assert!(Serializer::deserialize_batch_verify_response(
        &encoded_batch_response,
        &mut out_batch_response
    ));
    assert_eq!(out_batch_response, batch_response);

    let health_request = HealthCheckRequest;
    let encoded_health_request = Serializer::serialize_health_check_request(&health_request);
    let mut out_health_request = HealthCheckRequest;
    assert!(Serializer::deserialize_health_check_request(
        &encoded_health_request,
        &mut out_health_request
    ));
    assert_eq!(out_health_request, health_request);

    let health_response = HealthCheckResponse {
        status: ServingStatus::SERVING,
    };
    let encoded_health_response = Serializer::serialize_health_check_response(&health_response);
    let mut out_health_response = HealthCheckResponse::default();
    assert!(Serializer::deserialize_health_check_response(
        &encoded_health_response,
        &mut out_health_response
    ));
    assert_eq!(out_health_response, health_response);

    let mut wrong_type = out;
    assert!(!Serializer::deserialize_verify_request(
        &encoded_health_response,
        &mut wrong_type
    ));
}

#[test]
fn verify_wire_format_wire_namespace_mirrors_cpp_header_namespace() {
    assert_eq!(verify::wire::MAGIC, MAGIC);
    assert_eq!(verify::wire::VERSION, VERSION);
    assert_eq!(
        verify::wire::MessageType::VERIFY_REQUEST,
        MessageType::VerifyRequest
    );
    assert_eq!(verify::wire::VerifyStatus::GOOD, VerifyStatus::Good);
    assert_eq!(
        verify::wire::RequestFlags::INCLUDE_RESPONDER_CERT,
        RequestFlags::IncludeResponderCert
    );

    let request = verify::wire::VerifyRequest {
        certificate_chain: vec![verify::wire::CertificateData {
            der_bytes: vec![0x30, 0x01, 0x00],
        }],
        validation_timestamp: 99,
        flags: verify::wire::RequestFlags::INCLUDE_RESPONDER_CERT,
        nonce: vec![0x66; 32],
    };
    let encoded = verify::wire::Serializer::serialize(&request);
    let decoded: verify::wire::VerifyRequest =
        verify::wire::Serializer::deserialize(&encoded).unwrap();

    assert_eq!(decoded, request);
}

#[test]
fn verify_wire_format_batch_messages_concatenate_cpp_payloads_without_lengths() {
    let first = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: vec![0x30, 0x01, 0x00],
        }],
        validation_timestamp: 11,
        flags: RequestFlags::NONE,
        nonce: vec![0x11; 32],
    };
    let second = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: vec![0x30, 0x02, 0x00, 0x01],
        }],
        validation_timestamp: 22,
        flags: RequestFlags::INCLUDE_RESPONDER_CERT,
        nonce: vec![0x22; 32],
    };
    let batch = BatchVerifyRequest::new(vec![first.clone(), second.clone()]);

    let encoded = serialize(&batch);
    let mut expected = Vec::new();
    expected.extend(MAGIC);
    expected.push(VERSION);
    expected.push(MessageType::BatchRequest as u8);
    expected.extend(2u16.to_be_bytes());
    expected.extend(&serialize(&first)[6..]);
    expected.extend(&serialize(&second)[6..]);
    assert_eq!(encoded, expected);

    let decoded: BatchVerifyRequest = deserialize(&encoded).unwrap();
    assert_eq!(decoded, batch);

    let first_response = VerifyResponse {
        status: VerifyStatus::GOOD,
        reason: "ok".to_string(),
        revocation_time: 1,
        this_update: 2,
        next_update: 3,
        signature: vec![0xa1; 64],
        nonce: vec![0x33; 32],
        responder_cert_der: vec![0x30, 0x01],
    };
    let second_response = VerifyResponse {
        status: VerifyStatus::REVOKED,
        reason: "revoked".to_string(),
        revocation_time: 4,
        this_update: 5,
        next_update: 6,
        signature: Vec::new(),
        nonce: vec![0x44; 32],
        responder_cert_der: Vec::new(),
    };
    let responses = BatchVerifyResponse::new(vec![first_response.clone(), second_response.clone()]);

    let encoded_responses = serialize(&responses);
    let mut expected_responses = Vec::new();
    expected_responses.extend(MAGIC);
    expected_responses.push(VERSION);
    expected_responses.push(MessageType::BatchResponse as u8);
    expected_responses.extend(2u16.to_be_bytes());
    expected_responses.extend(&serialize(&first_response)[6..]);
    expected_responses.extend(&serialize(&second_response)[6..]);
    assert_eq!(encoded_responses, expected_responses);

    let decoded_responses: BatchVerifyResponse = deserialize(&encoded_responses).unwrap();
    assert_eq!(decoded_responses, responses);
}
