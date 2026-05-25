use super::*;

#[test]
fn verify_server_simple_revocation_handler_tracks_serials() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a01)
        .set_subject_from_string("CN=tracked")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x7a; 32])
        .build_with_signature(vec![0x7a; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    assert!(!handler.is_revoked(&cert.tbs.serial_number));

    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "key compromise", 42);
    assert!(handler.is_revoked(&cert.tbs.serial_number));

    handler.remove_revoked_certificate(&cert.tbs.serial_number);
    assert!(!handler.is_revoked(&cert.tbs.serial_number));

    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "cessation", 43);
    handler.clear();
    assert!(!handler.is_revoked(&cert.tbs.serial_number));
}

#[test]
fn verify_server_handler_reports_good_revoked_and_empty_chains() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a02)
        .set_subject_from_string("CN=device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x7b; 32])
        .build_with_signature(vec![0x7b; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    let before_good = current_unix_timestamp();
    let good = handler.verify_chain(std::slice::from_ref(&cert), 0);
    let after_good = current_unix_timestamp();
    assert_eq!(good.status, VerifyStatus::Good);
    assert!(good.this_update >= before_good);
    assert!(good.this_update <= after_good);
    assert_eq!(good.next_update, good.this_update + 86_400);

    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "superseded", 1234);
    let revoked = handler.verify_chain(std::slice::from_ref(&cert), 0);
    assert_eq!(revoked.status, VerifyStatus::Revoked);
    assert_eq!(revoked.reason, "superseded");
    assert_eq!(revoked.revocation_time, 1234);
    assert_eq!(revoked.next_update, revoked.this_update + 86_400);

    let empty = handler.verify_chain(&[], 0);
    assert_eq!(empty.status, VerifyStatus::Unknown);
    assert_eq!(empty.reason, "Empty certificate chain");
}

#[test]
fn verify_server_revocation_defaults_match_cpp_surface() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a22)
        .set_subject_from_string("CN=revocation-defaults")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x92; 32])
        .build_with_signature(vec![0x92; 64], true)
        .unwrap();
    let other = CertificateBuilder::new()
        .set_serial_u64(0x7a23)
        .set_subject_from_string("CN=revocation-now")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x93; 32])
        .build_with_signature(vec![0x93; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    let before_default = current_unix_timestamp();
    handler.add_revoked_certificate(cert.tbs.serial_number.clone());
    let after_default = current_unix_timestamp();

    let default_revoked = handler.verify_chain(std::slice::from_ref(&cert), 0);
    assert_eq!(default_revoked.status, VerifyStatus::Revoked);
    assert_eq!(default_revoked.reason, "unspecified");
    assert!(default_revoked.revocation_time >= before_default);
    assert!(default_revoked.revocation_time <= after_default);
    assert!(default_revoked.this_update >= before_default);
    assert!(default_revoked.this_update <= after_default);
    assert_eq!(
        default_revoked.next_update,
        default_revoked.this_update + 86_400
    );

    let before_now = current_unix_timestamp();
    handler.add_revoked_certificate_now(other.tbs.serial_number.clone(), "key compromise");
    let after_now = current_unix_timestamp();

    let now_revoked = handler.verify_chain(std::slice::from_ref(&other), 0);
    assert_eq!(now_revoked.status, VerifyStatus::Revoked);
    assert_eq!(now_revoked.reason, "key compromise");
    assert!(now_revoked.revocation_time >= before_now);
    assert!(now_revoked.revocation_time <= after_now);
    assert!(now_revoked.this_update >= before_now);
    assert!(now_revoked.this_update <= after_now);
    assert_eq!(now_revoked.next_update, now_revoked.this_update + 86_400);
}

#[test]
fn verify_server_request_processor_handles_health_good_and_revoked_requests() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a03)
        .set_subject_from_string("CN=processor-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x7c; 32])
        .build_with_signature(vec![0x7c; 64], true)
        .unwrap();

    let mut processor = RequestProcessor::new(SimpleRevocationHandler::new());
    assert_eq!(processor.stats().total_batch_requests, 0);
    assert_eq!(processor.stats().unknown_responses, 0);
    assert!(processor.stats().start_time > 0);
    assert_eq!(
        processor
            .set_signing_key(vec![0u8; 32])
            .unwrap_err()
            .message,
        "Invalid Ed25519 private key size"
    );

    let health_data = processor
        .process(methods::HEALTH_CHECK, &serialize(&HealthCheckRequest))
        .unwrap();
    let health: HealthCheckResponse = deserialize(&health_data).unwrap();
    assert_eq!(health.status, ServingStatus::Serving);

    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: cert.der().to_vec(),
        }],
        validation_timestamp: 1234,
        nonce: vec![0x33; 32],
        ..VerifyRequest::default()
    };
    let good_data = processor
        .process(methods::CHECK_CERTIFICATE, &serialize(&request))
        .unwrap();
    let good: VerifyResponse = deserialize(&good_data).unwrap();
    assert_eq!(good.status, VerifyStatus::Good);
    assert_eq!(good.nonce, request.nonce);

    processor.handler_mut().add_revoked_certificate_at(
        cert.tbs.serial_number.clone(),
        "processor revocation",
        5678,
    );
    let revoked_data = processor
        .process(methods::CHECK_CERTIFICATE, &serialize(&request))
        .unwrap();
    let revoked: VerifyResponse = deserialize(&revoked_data).unwrap();
    assert_eq!(revoked.status, VerifyStatus::Revoked);
    assert_eq!(revoked.reason, "processor revocation");

    assert_eq!(processor.stats().total_health_checks, 1);
    assert_eq!(processor.stats().total_requests, 2);
    assert_eq!(processor.stats().good_responses, 1);
    assert_eq!(processor.stats().revoked_responses, 1);
    assert_eq!(processor.get_stats(), processor.stats().clone());
}

#[test]
fn verify_server_request_processor_matches_cpp_error_response_behavior() {
    let mut processor = RequestProcessor::new(SimpleRevocationHandler::new());

    let bad_deserialize_data = processor
        .process(methods::CHECK_CERTIFICATE, b"not a wire request")
        .unwrap();
    let bad_deserialize: VerifyResponse = deserialize(&bad_deserialize_data).unwrap();
    assert_eq!(bad_deserialize.status, VerifyStatus::Unknown);
    assert_eq!(bad_deserialize.reason, "Failed to deserialize request");

    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: vec![0xde, 0xad, 0xbe, 0xef],
        }],
        nonce: vec![0x44; 32],
        ..VerifyRequest::default()
    };
    let bad_cert_data = processor
        .process(methods::CHECK_CERTIFICATE, &serialize(&request))
        .unwrap();
    let bad_cert: VerifyResponse = deserialize(&bad_cert_data).unwrap();
    assert_eq!(bad_cert.status, VerifyStatus::Unknown);
    assert!(bad_cert.reason.starts_with("Failed to parse certificate: "));
    assert_eq!(bad_cert.nonce, request.nonce);

    let batch = BatchVerifyRequest {
        requests: vec![VerifyRequest {
            certificate_chain: vec![CertificateData {
                der_bytes: vec![0xca, 0xfe],
            }],
            nonce: vec![0x45; 32],
            ..VerifyRequest::default()
        }],
    };
    let batch_data = processor
        .process(methods::CHECK_BATCH, &serialize(&batch))
        .unwrap();
    let batch_response: BatchVerifyResponse = deserialize(&batch_data).unwrap();
    assert_eq!(batch_response.responses.len(), 1);
    assert_eq!(batch_response.responses[0].status, VerifyStatus::Unknown);
    assert_eq!(
        batch_response.responses[0].reason,
        "Empty certificate chain"
    );
    assert_eq!(batch_response.responses[0].nonce, vec![0x45; 32]);

    let bad_batch_data = processor
        .process(methods::CHECK_BATCH, b"bad batch")
        .unwrap();
    let bad_batch: BatchVerifyResponse = deserialize(&bad_batch_data).unwrap();
    assert!(bad_batch.responses.is_empty());

    let health_data = processor
        .process(methods::HEALTH_CHECK, b"ignored")
        .unwrap();
    let health: HealthCheckResponse = deserialize(&health_data).unwrap();
    assert_eq!(health.status, ServingStatus::Serving);

    assert!(
        processor
            .process(0xffff_ffff, b"ignored")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn verify_server_request_processor_uses_handler_batch_override_like_cpp() {
    struct BatchOverrideHandler {
        verify_chain_calls: std::cell::Cell<u32>,
        verify_batch_calls: std::cell::Cell<u32>,
    }

    impl VerificationHandler for BatchOverrideHandler {
        fn verify_chain(
            &self,
            _chain: &[Certificate],
            _validation_timestamp: u64,
        ) -> VerifyResponse {
            self.verify_chain_calls
                .set(self.verify_chain_calls.get() + 1);
            VerifyResponse {
                status: VerifyStatus::Unknown,
                reason: "single-chain path should not be used".to_string(),
                ..VerifyResponse::default()
            }
        }

        fn verify_batch(&self, chains: &[Vec<Certificate>]) -> Vec<VerifyResponse> {
            self.verify_batch_calls
                .set(self.verify_batch_calls.get() + 1);
            chains
                .iter()
                .enumerate()
                .map(|(idx, chain)| VerifyResponse {
                    status: if chain.is_empty() {
                        VerifyStatus::Unknown
                    } else {
                        VerifyStatus::Good
                    },
                    reason: format!("batch override {idx}"),
                    ..VerifyResponse::default()
                })
                .collect()
        }
    }

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a2d)
        .set_subject_from_string("CN=batch-override-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x9d; 32])
        .build_with_signature(vec![0x9d; 64], true)
        .unwrap();

    let handler = BatchOverrideHandler {
        verify_chain_calls: std::cell::Cell::new(0),
        verify_batch_calls: std::cell::Cell::new(0),
    };
    let mut processor = RequestProcessor::new(handler);
    let request = BatchVerifyRequest {
        requests: vec![
            VerifyRequest {
                certificate_chain: vec![CertificateData {
                    der_bytes: cert.der().to_vec(),
                }],
                validation_timestamp: 1234,
                nonce: vec![0xaa; 32],
                ..VerifyRequest::default()
            },
            VerifyRequest {
                certificate_chain: vec![CertificateData {
                    der_bytes: vec![0xde, 0xad],
                }],
                validation_timestamp: 5678,
                nonce: vec![0xbb; 32],
                ..VerifyRequest::default()
            },
        ],
    };

    let response_data = processor
        .process(methods::CHECK_BATCH, &serialize(&request))
        .unwrap();
    let response: BatchVerifyResponse = deserialize(&response_data).unwrap();

    assert_eq!(processor.handler().verify_chain_calls.get(), 0);
    assert_eq!(processor.handler().verify_batch_calls.get(), 1);
    assert_eq!(response.responses.len(), 2);
    assert_eq!(response.responses[0].status, VerifyStatus::Good);
    assert_eq!(response.responses[0].reason, "batch override 0");
    assert_eq!(response.responses[0].nonce, vec![0xaa; 32]);
    assert_eq!(response.responses[1].status, VerifyStatus::Unknown);
    assert_eq!(response.responses[1].reason, "batch override 1");
    assert_eq!(response.responses[1].nonce, vec![0xbb; 32]);
    assert_eq!(processor.stats().total_batch_requests, 1);
    assert_eq!(processor.stats().good_responses, 1);
    assert_eq!(processor.stats().unknown_responses, 1);
}

#[test]
fn verify_server_direct_transport_client_and_verifier_flows() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a04)
        .set_subject_from_string("CN=direct-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x7d; 32])
        .build_with_signature(vec![0x7d; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "direct revocation", 9000);
    let transport = DirectTransport::new(RequestProcessor::new(handler));
    let mut client = Client::new(transport);

    assert!(client.is_ready());
    assert!(client.health_check().unwrap());
    let response = client
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert_eq!(response.status, VerifyStatus::Revoked);
    assert_eq!(response.reason, "direct revocation");

    let mut verifier = Verifier::new();
    assert!(verifier.health_check().unwrap());
    verifier.handler_mut().add_revoked_certificate_at(
        cert.tbs.serial_number.clone(),
        "verifier revocation",
        9001,
    );
    let verifier_response = verifier
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert_eq!(verifier_response.status, VerifyStatus::Revoked);
    assert_eq!(verifier_response.reason, "verifier revocation");
}

#[test]
fn verify_direct_transport_unconfigured_state_matches_cpp_null_processor_surface() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a2e)
        .set_subject_from_string("CN=unconfigured-direct-transport")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x9e; 32])
        .build_with_signature(vec![0x9e; 64], true)
        .unwrap();

    let mut transport = DirectTransport::<SimpleRevocationHandler>::unconfigured();
    assert!(!transport.is_ready());
    assert!(
        transport
            .call(methods::HEALTH_CHECK, &serialize(&HealthCheckRequest))
            .unwrap()
            .is_empty()
    );
    assert_eq!(transport.last_error(), "No processor configured");

    let mut client = Client::new(transport);
    assert!(!client.is_ready());
    assert_eq!(
        client.health_check().unwrap_err().message,
        "Transport is not ready"
    );
    assert_eq!(
        client
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap_err()
            .message,
        "Transport is not ready"
    );

    client
        .transport_mut()
        .set_processor(RequestProcessor::new(SimpleRevocationHandler::new()));
    assert!(client.is_ready());
    assert!(client.health_check().unwrap());

    client.transport_mut().clear_processor();
    assert!(!client.is_ready());
}

#[test]
fn verify_direct_transport_catches_processor_failures_like_cpp_exception_boundary() {
    struct PanicHandler;

    impl VerificationHandler for PanicHandler {
        fn verify_chain(
            &self,
            _chain: &[Certificate],
            _validation_timestamp: u64,
        ) -> VerifyResponse {
            panic!("handler exploded")
        }
    }

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a30)
        .set_subject_from_string("CN=panic-direct-transport")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0xa0; 32])
        .build_with_signature(vec![0xa0; 64], true)
        .unwrap();
    let request = VerifyRequest {
        certificate_chain: vec![CertificateData {
            der_bytes: cert.der().to_vec(),
        }],
        nonce: vec![0xa0; 32],
        ..VerifyRequest::default()
    };

    let mut transport = DirectTransport::new(RequestProcessor::new(PanicHandler));
    let response = transport
        .call(methods::CHECK_CERTIFICATE, &serialize(&request))
        .unwrap();

    assert!(response.is_empty());
    assert_eq!(transport.last_error(), "handler exploded");

    let mut client = Client::new(transport);
    assert_eq!(
        client
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap_err()
            .message,
        "Transport call failed: handler exploded"
    );
}

#[test]
fn verifier_convenience_methods_use_cpp_client_error_surface_on_transport_failure() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a31)
        .set_subject_from_string("CN=verifier-client-error-surface")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0xa1; 32])
        .build_with_signature(vec![0xa1; 64], true)
        .unwrap();

    struct VerifyPanicHandler;

    impl VerificationHandler for VerifyPanicHandler {
        fn verify_chain(
            &self,
            _chain: &[Certificate],
            _validation_timestamp: u64,
        ) -> VerifyResponse {
            panic!("verifier handler exploded")
        }
    }

    let mut verify_panic = Verifier::with_handler(VerifyPanicHandler);
    assert_eq!(
        verify_panic
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap_err()
            .message,
        "Transport call failed: verifier handler exploded"
    );

    struct BatchPanicHandler;

    impl VerificationHandler for BatchPanicHandler {
        fn verify_chain(
            &self,
            _chain: &[Certificate],
            _validation_timestamp: u64,
        ) -> VerifyResponse {
            VerifyResponse::default()
        }

        fn verify_batch(&self, _chains: &[Vec<Certificate>]) -> Vec<VerifyResponse> {
            panic!("verifier batch exploded")
        }
    }

    let mut batch_panic = Verifier::with_handler(BatchPanicHandler);
    assert_eq!(
        batch_panic
            .verify_batch(&[vec![cert.clone()]])
            .unwrap_err()
            .message,
        "Transport call failed: verifier batch exploded"
    );

    struct HealthPanicHandler;

    impl VerificationHandler for HealthPanicHandler {
        fn verify_chain(
            &self,
            _chain: &[Certificate],
            _validation_timestamp: u64,
        ) -> VerifyResponse {
            VerifyResponse::default()
        }

        fn is_healthy(&self) -> bool {
            panic!("verifier health exploded")
        }
    }

    let mut health_panic = Verifier::with_handler(HealthPanicHandler);
    assert_eq!(
        health_panic.health_check().unwrap_err().message,
        "Health check failed: verifier health exploded"
    );
}

#[test]
fn verify_direct_transport_client_server_revocation_flow_from_central_port() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x22)
        .set_subject_from_string("CN=revoked-device")
        .unwrap()
        .set_validity(der_time(2026, 5, 24), der_time(2027, 5, 24))
        .set_subject_public_key_ed25519(vec![0x77; 32])
        .build_with_signature(vec![0xee; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    assert!(!handler.is_revoked(&cert.tbs.serial_number));
    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "Test revocation", 1234);
    assert!(handler.is_revoked(&cert.tbs.serial_number));

    let processor = RequestProcessor::new(handler);
    let transport = DirectTransport::new(processor);
    let mut client = Client::new(transport);
    assert!(client.is_ready());
    assert!(client.health_check().unwrap());

    let response = client.verify_chain_at(&[cert], 1234).unwrap();
    assert_eq!(response.status, VerifyStatus::Revoked);
    assert!(!response.valid);
    assert_eq!(response.reason, "Test revocation");

    let stats = client.transport_mut().processor().stats();
    assert_eq!(stats.total_health_checks, 1);
    assert_eq!(stats.total_requests, 1);
    assert_eq!(stats.revoked_responses, 1);
}

#[test]
fn verifier_helper_forwards_signing_responder_and_client_calls() {
    let responder_key = generate_ed25519_keypair().unwrap();
    let responder_cert = CertificateBuilder::new()
        .set_serial_u64(0x31)
        .set_subject_from_string("CN=verifier-responder")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(responder_key.public_key.clone())
        .build_ed25519_with_self_signed(&responder_key, true)
        .unwrap();
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x32)
        .set_subject_from_string("CN=verifier-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x32; 32])
        .build_with_signature(vec![0x32; 64], true)
        .unwrap();

    let mut verifier = Verifier::new();
    verifier
        .set_signing_key(responder_key.private_key.clone())
        .unwrap();
    verifier.set_responder_certificate(responder_cert);
    assert!(verifier.health_check().unwrap());
    verifier.handler_mut().add_revoked_certificate_at(
        cert.tbs.serial_number.clone(),
        "Verifier helper revocation",
        777,
    );

    let response = verifier
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert_eq!(response.status, VerifyStatus::Revoked);
    assert_eq!(response.reason, "Verifier helper revocation");
    assert_eq!(response.signature.len(), 64);

    let batch = verifier.verify_batch(&[vec![cert]]).unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0].status, VerifyStatus::Revoked);
}

#[test]
fn verifier_exposes_cpp_style_client_and_revocation_handler_accessors() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a24)
        .set_subject_from_string("CN=borrowed-client-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x94; 32])
        .build_with_signature(vec![0x94; 64], true)
        .unwrap();

    let mut verifier = Verifier::new();
    let revocation_handler = verifier.as_revocation_handler().unwrap();
    revocation_handler.add_revoked_certificate_at(
        cert.tbs.serial_number.clone(),
        "borrowed client revocation",
        9191,
    );

    {
        let mut client = verifier.client();
        assert!(client.is_ready());
        assert!(client.health_check().unwrap());
        let response = client
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap();
        assert_eq!(response.status, VerifyStatus::Revoked);
        assert_eq!(response.reason, "borrowed client revocation");
    }

    assert_eq!(verifier.transport().processor().stats().total_requests, 1);
    assert_eq!(
        verifier.transport().processor().stats().total_health_checks,
        1
    );
}

#[test]
fn verifier_accepts_custom_handler_like_cpp_constructor() {
    struct CustomHandler {
        verify_chain_calls: std::cell::Cell<u32>,
    }

    impl VerificationHandler for CustomHandler {
        fn verify_chain(&self, chain: &[Certificate], validation_timestamp: u64) -> VerifyResponse {
            self.verify_chain_calls
                .set(self.verify_chain_calls.get() + 1);
            VerifyResponse {
                status: VerifyStatus::Good,
                reason: format!("custom {} @ {validation_timestamp}", chain.len()),
                this_update: validation_timestamp,
                next_update: validation_timestamp + 86_400,
                ..VerifyResponse::default()
            }
        }

        fn is_healthy(&self) -> bool {
            false
        }
    }

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a2f)
        .set_subject_from_string("CN=custom-verifier-handler")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x9f; 32])
        .build_with_signature(vec![0x9f; 64], true)
        .unwrap();

    let mut verifier = Verifier::with_handler(CustomHandler {
        verify_chain_calls: std::cell::Cell::new(0),
    });
    assert!(verifier.as_revocation_handler().is_none());
    assert!(!verifier.health_check().unwrap());

    let response = verifier
        .verify_chain_at(std::slice::from_ref(&cert), 4242)
        .unwrap();
    assert!(response.valid);
    assert_eq!(response.status, VerifyStatus::Good);
    assert_eq!(response.reason, "custom 1 @ 4242");
    assert_eq!(response.this_update, 4242);
    assert_eq!(response.next_update, 90_642);
    assert_eq!(verifier.handler().verify_chain_calls.get(), 1);

    let batch = verifier.verify_batch(&[vec![cert]]).unwrap();
    assert_eq!(batch.len(), 1);
    assert!(batch[0].reason.starts_with("custom 1 @ "));
    assert_eq!(verifier.handler().verify_chain_calls.get(), 2);
}

#[test]
fn verify_client_and_verifier_support_cpp_default_validation_time_surface() {
    struct TimestampHandler {
        seen_timestamp: std::cell::Cell<u64>,
    }

    impl VerificationHandler for TimestampHandler {
        fn verify_chain(&self, chain: &[Certificate], validation_timestamp: u64) -> VerifyResponse {
            self.seen_timestamp.set(validation_timestamp);
            VerifyResponse {
                status: VerifyStatus::Good,
                reason: format!("{} certs @ now", chain.len()),
                this_update: validation_timestamp,
                next_update: validation_timestamp + 60,
                ..VerifyResponse::default()
            }
        }
    }

    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a30)
        .set_subject_from_string("CN=default-validation-time")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x30; 32])
        .build_with_signature(vec![0x30; 64], true)
        .unwrap();

    let mut verifier = Verifier::with_handler(TimestampHandler {
        seen_timestamp: std::cell::Cell::new(0),
    });
    let before = current_unix_timestamp();
    let response = verifier.verify_chain(std::slice::from_ref(&cert)).unwrap();
    let after = current_unix_timestamp();
    assert!(response.valid);
    assert!(response.this_update >= before);
    assert!(response.this_update <= after);
    assert_eq!(
        verifier.handler().seen_timestamp.get(),
        response.this_update
    );

    let result = verifier.verify_chain_result(std::slice::from_ref(&cert));
    assert!(result.success);
    assert!(result.value.valid);

    let mut client = verifier.client();
    let client_result = client.verify_chain_result(std::slice::from_ref(&cert));
    assert!(client_result.success);
    assert!(client_result.value.valid);
}

#[test]
fn verify_request_handler_transport_matches_cpp_function_surface() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a25)
        .set_subject_from_string("CN=request-handler-transport")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x95; 32])
        .build_with_signature(vec![0x95; 64], true)
        .unwrap();

    let mut processor = RequestProcessor::new(SimpleRevocationHandler::new());
    processor.handler_mut().add_revoked_certificate_at(
        cert.tbs.serial_number.clone(),
        "handler transport revocation",
        7171,
    );

    let transport = RequestHandlerTransport::new(move |method_id, request: &[u8]| {
        processor.process(method_id, request).unwrap_or_default()
    });
    let mut client = Client::new(transport);

    assert!(client.is_ready());
    assert!(client.health_check().unwrap());
    let response = client
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert_eq!(response.status, VerifyStatus::Revoked);
    assert_eq!(response.reason, "handler transport revocation");

    client.transport_mut().set_ready(false);
    assert!(!client.is_ready());
    let health = client.health_check_result();
    assert!(!health.success);
    assert_eq!(health.error, "Transport is not ready");

    let mut request_handler: Box<RequestHandler> =
        Box::new(|method_id, _request| method_id.to_be_bytes().to_vec());
    assert_eq!(
        request_handler(methods::HEALTH_CHECK, b""),
        vec![0, 0, 0, 3]
    );
}

#[test]
fn verify_boxed_transport_supports_cpp_shared_pointer_client_shape() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a32)
        .set_subject_from_string("CN=boxed-transport-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0xa2; 32])
        .build_with_signature(vec![0xa2; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "boxed transport", 8080);

    let boxed_transport: Box<dyn Transport> =
        Box::new(DirectTransport::new(RequestProcessor::new(handler)));
    let mut client = Client::new(boxed_transport);

    assert!(client.is_ready());
    assert!(client.health_check().unwrap());
    let response = client
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert_eq!(response.status, VerifyStatus::Revoked);
    assert_eq!(response.reason, "boxed transport");
}

#[test]
fn verify_shared_transport_clones_share_the_same_transport_state() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a33)
        .set_subject_from_string("CN=shared-transport-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0xa3; 32])
        .build_with_signature(vec![0xa3; 64], true)
        .unwrap();

    let mut handler = SimpleRevocationHandler::new();
    handler.add_revoked_certificate_at(cert.tbs.serial_number.clone(), "shared transport", 8181);

    let shared = SharedTransport::new(DirectTransport::new(RequestProcessor::new(handler)));
    let inspector = shared.clone();
    let mut health_client = Client::new(shared.clone());
    let mut verify_client = Client::new(shared);

    assert!(health_client.is_ready());
    assert!(health_client.health_check().unwrap());

    let response = verify_client
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert_eq!(response.status, VerifyStatus::Revoked);
    assert_eq!(response.reason, "shared transport");

    let shared_transport = inspector.lock().unwrap();
    let stats = shared_transport.processor().stats();
    assert_eq!(stats.total_health_checks, 1);
    assert_eq!(stats.total_requests, 1);
    assert_eq!(stats.revoked_responses, 1);
}

#[test]
fn verify_client_transport_and_decode_errors_match_cpp_surface() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a26)
        .set_subject_from_string("CN=transport-error-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x96; 32])
        .build_with_signature(vec![0x96; 64], true)
        .unwrap();

    let mut empty_client = Client::new(RequestHandlerTransport::new(|_, _| Vec::new()));
    assert_eq!(
        empty_client
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap_err()
            .message,
        "Transport call failed: "
    );
    assert_eq!(
        empty_client.health_check().unwrap_err().message,
        "Health check failed: "
    );
    assert_eq!(
        empty_client
            .verify_batch(&[vec![cert.clone()]])
            .unwrap_err()
            .message,
        "Transport call failed: "
    );

    let mut bad_response_client = Client::new(RequestHandlerTransport::new(|_, _| {
        vec![0xde, 0xad, 0xbe, 0xef]
    }));
    assert_eq!(
        bad_response_client
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap_err()
            .message,
        "Failed to deserialize response"
    );
    assert_eq!(
        bad_response_client.health_check().unwrap_err().message,
        "Failed to deserialize health check response"
    );
    assert_eq!(
        bad_response_client
            .verify_batch(&[vec![cert]])
            .unwrap_err()
            .message,
        "Failed to deserialize batch response"
    );
}

#[test]
fn verify_client_rejects_bad_and_accepts_good_response_signature() {
    let signing_key = hex_bytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\
         d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );
    let responder_public_key =
        hex_bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let responder_cert = CertificateBuilder::new()
        .set_serial_u64(0x23)
        .set_subject_from_string("CN=responder")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(responder_public_key)
        .build_with_signature(vec![0x23; 64], true)
        .unwrap();
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x24)
        .set_subject_from_string("CN=signed-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x24; 32])
        .build_with_signature(vec![0x24; 64], true)
        .unwrap();

    let mut processor = RequestProcessor::new(SimpleRevocationHandler::new());
    processor.set_signing_key(signing_key).unwrap();
    let transport = DirectTransport::new(processor);
    let mut client = Client::new(transport);
    client.set_responder_cert(responder_cert);

    let response = client
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    assert!(response.valid);
    assert_eq!(response.signature.len(), 64);

    let wrong_responder_cert = CertificateBuilder::new()
        .set_serial_u64(0x25)
        .set_subject_from_string("CN=wrong-responder")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x25; 32])
        .build_with_signature(vec![0x25; 64], true)
        .unwrap();
    client.set_responder_cert(wrong_responder_cert);
    let err = client
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap_err();
    assert!(
        err.message
            .contains("Response signature verification failed")
    );
}

#[test]
fn verify_client_batch_keeps_cpp_surface_without_response_signature_check() {
    let responder_cert = CertificateBuilder::new()
        .set_serial_u64(0x7a28)
        .set_subject_from_string("CN=batch-responder")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x98; 32])
        .build_with_signature(vec![0x98; 64], true)
        .unwrap();
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a29)
        .set_subject_from_string("CN=batch-signature-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x99; 32])
        .build_with_signature(vec![0x99; 64], true)
        .unwrap();

    let captured_timestamps = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u64>::new()));
    let timestamps_by_transport = captured_timestamps.clone();
    let transport = RequestHandlerTransport::new(move |method_id, request: &[u8]| {
        assert_eq!(method_id, methods::CHECK_BATCH);
        let batch: BatchVerifyRequest = deserialize(request).unwrap();
        let responses = batch
            .requests
            .into_iter()
            .map(|request| VerifyResponse {
                status: VerifyStatus::Good,
                reason: "batch ok".to_string(),
                this_update: {
                    timestamps_by_transport
                        .borrow_mut()
                        .push(request.validation_timestamp);
                    request.validation_timestamp
                },
                next_update: request.validation_timestamp + 86_400,
                signature: vec![0x42; 64],
                nonce: request.nonce,
                ..VerifyResponse::default()
            })
            .collect();
        serialize(&BatchVerifyResponse { responses })
    });
    let mut client = Client::new(transport);
    client.set_responder_cert(responder_cert);

    let before = current_unix_timestamp();
    let responses = client.verify_batch(&[vec![cert]]).unwrap();
    let after = current_unix_timestamp();
    assert_eq!(responses.len(), 1);
    assert!(responses[0].valid);
    assert_eq!(responses[0].reason, "batch ok");
    assert_eq!(responses[0].signature, vec![0x42; 64]);
    let timestamps = captured_timestamps.borrow();
    assert_eq!(timestamps.len(), 1);
    assert!(timestamps[0] >= before);
    assert!(timestamps[0] <= after);
    assert_eq!(responses[0].this_update, timestamps[0]);
}

#[test]
fn verify_client_result_wrappers_match_cpp_surface() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a06)
        .set_subject_from_string("CN=result-wrapper-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x7f; 32])
        .build_with_signature(vec![0x7f; 64], true)
        .unwrap();

    let transport = DirectTransport::new(RequestProcessor::new(SimpleRevocationHandler::new()));
    let mut client = Client::new(transport);

    let health = client.health_check_result();
    assert!(health.success);
    assert!(health.value);
    assert!(health.error.is_empty());
    assert!(health.into_result().unwrap());

    let response = client.verify_chain_result_at(std::slice::from_ref(&cert), 1234);
    assert!(response.success);
    assert!(response.value.valid);
    assert_eq!(response.value.status, VerifyStatus::Good);
    assert!(response.error.is_empty());

    let batch = client.verify_batch_result(&[vec![cert.clone()]]);
    assert!(batch.success);
    assert_eq!(batch.value.len(), 1);
    assert_eq!(batch.value[0].status, VerifyStatus::Good);

    let empty_chain = client.verify_chain_result_at(&[], 1234);
    assert!(!empty_chain.success);
    assert_eq!(empty_chain.error, "Certificate chain is empty");
    assert_eq!(empty_chain.value, ClientResponse::default());
    assert_eq!(
        empty_chain.into_result().unwrap_err().message,
        "Certificate chain is empty"
    );

    let empty_batch = client.verify_batch_result(&[]);
    assert!(!empty_batch.success);
    assert_eq!(empty_batch.error, "No chains provided");
    assert!(empty_batch.value.is_empty());
}

#[test]
fn verify_client_config_and_result_aliases_match_cpp_surface_shape() {
    let default_config = ClientConfig::default();
    assert_eq!(default_config.timeout_seconds, 5);
    assert_eq!(default_config.timeout(), 5);
    assert_eq!(default_config.max_retry_attempts, 3);

    let custom_config = ClientConfig::new(12, 9);
    assert_eq!(custom_config.timeout_seconds, 12);
    assert_eq!(custom_config.timeout(), 12);
    assert_eq!(custom_config.max_retry_attempts, 9);

    let default_client = Client::new(DirectTransport::new(RequestProcessor::new(
        SimpleRevocationHandler::new(),
    )));
    assert_eq!(default_client.config(), &ClientConfig::default());

    let configured_client = Client::with_config(
        DirectTransport::new(RequestProcessor::new(SimpleRevocationHandler::new())),
        custom_config.clone(),
    );
    assert_eq!(configured_client.config(), &custom_config);

    let default_result: ClientResult<ClientResponse> = ClientResult::default();
    assert!(!default_result.success);
    assert_eq!(default_result.value, ClientResponse::default());
    assert!(default_result.error.is_empty());

    let alias_result: OperationResult<Response> = ClientResult::ok(ClientResponse {
        valid: true,
        status: VerifyStatus::Good,
        reason: "ok".to_string(),
        ..ClientResponse::default()
    });
    assert!(alias_result.success);
    assert!(alias_result.value.valid);
    assert_eq!(alias_result.value.status, VerifyStatus::Good);
    assert_eq!(alias_result.into_result().unwrap().reason, "ok");
}

#[test]
fn verify_client_generates_random_request_nonces_like_cpp() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a27)
        .set_subject_from_string("CN=random-nonce-client")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x97; 32])
        .build_with_signature(vec![0x97; 64], true)
        .unwrap();

    let captured_nonces = std::rc::Rc::new(std::cell::RefCell::new(Vec::<Vec<u8>>::new()));
    let captured_by_transport = captured_nonces.clone();
    let transport =
        RequestHandlerTransport::new(move |method_id, request: &[u8]| match method_id {
            methods::CHECK_CERTIFICATE => {
                let request: VerifyRequest = deserialize(request).unwrap();
                captured_by_transport
                    .borrow_mut()
                    .push(request.nonce.clone());
                serialize(&VerifyResponse {
                    status: VerifyStatus::Good,
                    reason: "Certificate is valid".to_string(),
                    this_update: 1,
                    next_update: 86_401,
                    nonce: request.nonce,
                    ..VerifyResponse::default()
                })
            }
            methods::CHECK_BATCH => {
                let batch: BatchVerifyRequest = deserialize(request).unwrap();
                let responses = batch
                    .requests
                    .into_iter()
                    .map(|request| {
                        captured_by_transport
                            .borrow_mut()
                            .push(request.nonce.clone());
                        VerifyResponse {
                            status: VerifyStatus::Good,
                            reason: "Certificate is valid".to_string(),
                            this_update: 1,
                            next_update: 86_401,
                            nonce: request.nonce,
                            ..VerifyResponse::default()
                        }
                    })
                    .collect();
                serialize(&BatchVerifyResponse { responses })
            }
            _ => Vec::new(),
        });
    let mut client = Client::new(transport);

    assert!(
        client
            .verify_chain_at(std::slice::from_ref(&cert), 1234)
            .unwrap()
            .valid
    );
    assert!(
        client
            .verify_chain_at(std::slice::from_ref(&cert), 1235)
            .unwrap()
            .valid
    );
    assert_eq!(client.verify_batch(&[vec![cert]]).unwrap().len(), 1);

    let nonces = captured_nonces.borrow();
    assert_eq!(nonces.len(), 3);
    for nonce in nonces.iter() {
        assert_eq!(nonce.len(), 32);
        #[cfg(unix)]
        assert_ne!(nonce, &vec![0; 32]);
    }
    #[cfg(unix)]
    {
        assert_ne!(nonces[0], nonces[1]);
        assert_ne!(nonces[1], nonces[2]);
    }
}

#[test]
fn verify_direct_verifier_generates_random_request_nonces_like_cpp() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a2a)
        .set_subject_from_string("CN=random-nonce-verifier")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x9a; 32])
        .build_with_signature(vec![0x9a; 64], true)
        .unwrap();

    let mut verifier = Verifier::new();
    let first = verifier
        .verify_chain_at(std::slice::from_ref(&cert), 1234)
        .unwrap();
    let second = verifier
        .verify_chain_at(std::slice::from_ref(&cert), 1235)
        .unwrap();
    let batch = verifier.verify_batch(&[vec![cert]]).unwrap();

    let nonces = [&first.nonce, &second.nonce, &batch[0].nonce];
    for nonce in nonces {
        assert_eq!(nonce.len(), 32);
        #[cfg(unix)]
        assert_ne!(nonce, &vec![0; 32]);
    }
    #[cfg(unix)]
    {
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(second.nonce, batch[0].nonce);
    }
}

#[test]
fn verify_direct_verifier_batch_keeps_cpp_surface_without_response_signature_check() {
    let responder_cert = CertificateBuilder::new()
        .set_serial_u64(0x7a2b)
        .set_subject_from_string("CN=verifier-batch-responder")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x9b; 32])
        .build_with_signature(vec![0x9b; 64], true)
        .unwrap();
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a2c)
        .set_subject_from_string("CN=verifier-batch-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x9c; 32])
        .build_with_signature(vec![0x9c; 64], true)
        .unwrap();

    let mut verifier = Verifier::new();
    verifier.set_responder_certificate(responder_cert);

    let responses = verifier.verify_batch(&[vec![cert]]).unwrap();
    assert_eq!(responses.len(), 1);
    assert!(responses[0].valid);
    assert!(responses[0].signature.is_empty());
}

#[test]
fn verify_direct_verifier_result_wrappers_match_cpp_surface() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a07)
        .set_subject_from_string("CN=verifier-result-wrapper-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x80; 32])
        .build_with_signature(vec![0x80; 64], true)
        .unwrap();

    let mut verifier = Verifier::new();
    assert!(verifier.health_check_result().into_result().unwrap());

    let good = verifier.verify_chain_result_at(std::slice::from_ref(&cert), 1234);
    assert!(good.success);
    assert!(good.value.valid);

    verifier.handler_mut().add_revoked_certificate_at(
        cert.tbs.serial_number.clone(),
        "verifier result revocation",
        55,
    );
    let revoked = verifier.verify_batch_result(&[vec![cert.clone()]]);
    assert!(revoked.success);
    assert_eq!(revoked.value[0].status, VerifyStatus::Revoked);
    assert_eq!(revoked.value[0].reason, "verifier result revocation");

    let empty_chain = verifier.verify_chain_result_at(&[], 1234);
    assert!(!empty_chain.success);
    assert_eq!(empty_chain.error, "Certificate chain is empty");

    let empty_batch = verifier.verify_batch_result(&[]);
    assert!(!empty_batch.success);
    assert_eq!(empty_batch.error, "No chains provided");
}

#[test]
fn verify_server_certificate_check_revocation_uses_client() {
    let cert = CertificateBuilder::new()
        .set_serial_u64(0x7a05)
        .set_subject_from_string("CN=check-revocation-device")
        .unwrap()
        .set_validity(der_time(2020, 1, 1), der_time(2035, 1, 1))
        .set_subject_public_key_ed25519(vec![0x7e; 32])
        .build_with_signature(vec![0x7e; 64], true)
        .unwrap();

    let transport = DirectTransport::new(RequestProcessor::new(SimpleRevocationHandler::new()));
    let mut client = Client::new(transport);
    assert!(cert.check_revocation(&mut client).unwrap());

    client
        .transport_mut()
        .processor_mut()
        .handler_mut()
        .add_revoked_certificate_at(
            cert.tbs.serial_number.clone(),
            "certificate method revocation",
            42,
        );
    assert!(!cert.check_revocation(&mut client).unwrap());
}
