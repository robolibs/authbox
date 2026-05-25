use super::*;

fn test_cert_with_extensions(extensions: Vec<RawExtension>, subject_cn: &str) -> Certificate {
    Certificate {
        tbs: TbsCertificate {
            version: 3,
            subject: DistinguishedName::from_string(&format!("CN={subject_cn}")).unwrap(),
            extensions,
            ..TbsCertificate::default()
        },
        ..Certificate::default()
    }
}

#[test]
fn cert_enterprise_extension_accessors_exist_and_are_empty_when_absent() {
    let (cert, _key) = helpers::make_self_signed_certificate("EnterpriseTest", 42);

    assert!(cert.issuer_alt_names().is_empty());
    assert!(cert.policy_mappings().is_empty());
    assert!(cert.policy_constraints().is_none());
    assert!(cert.inhibit_any_policy().is_none());
}

#[test]
fn cert_enterprise_extensions_cpp_named_wrapper_surfaces_work() {
    let issuer_alt_name = IssuerAltNameExtension::new(
        false,
        vec![
            GeneralName::new(GeneralNameType::Email, "ops@example.com"),
            GeneralName::new(GeneralNameType::URI, "https://issuer.example"),
        ],
    );
    assert_eq!(issuer_alt_name.id(), ExtensionId::IssuerAltName);
    assert!(!issuer_alt_name.critical());
    assert_eq!(issuer_alt_name.names().len(), 2);
    assert_eq!(issuer_alt_name.names()[0].type_, GeneralNameType::Email);

    let mappings = PolicyMappingsExtension::new(
        true,
        vec![PolicyMapping::new(vec![1, 2, 3, 4], vec![1, 2, 3, 5])],
    );
    assert_eq!(mappings.id(), ExtensionId::PolicyMappings);
    assert!(mappings.critical());
    assert_eq!(
        mappings.mappings()[0].issuer_domain_policy,
        vec![1, 2, 3, 4]
    );
    assert_eq!(
        mappings.mappings()[0].subject_domain_policy,
        vec![1, 2, 3, 5]
    );

    let constraints = PolicyConstraintsExtension::new(true, Some(2), Some(5));
    assert_eq!(constraints.id(), ExtensionId::PolicyConstraints);
    assert!(constraints.critical());
    assert_eq!(constraints.require_explicit_policy(), Some(2));
    assert_eq!(constraints.inhibit_policy_mapping(), Some(5));

    let flat_constraints: PolicyConstraints = constraints.clone().into();
    let roundtrip_constraints = PolicyConstraintsExtension::from(flat_constraints);
    assert_eq!(roundtrip_constraints, constraints);

    let inhibit_any_policy = InhibitAnyPolicyExtension::new(true, 4);
    assert_eq!(inhibit_any_policy.id(), ExtensionId::InhibitAnyPolicy);
    assert!(inhibit_any_policy.critical());
    assert_eq!(inhibit_any_policy.skip_certs(), 4);
}

#[test]
fn cert_enterprise_extensions_decode_enterprise_helpers() {
    let issuer_alt_name = RawExtension {
        oid: Oid::new([2, 5, 29, 18]),
        id: ExtensionId::IssuerAltName,
        critical: false,
        value: der::encode_sequence(&der::concat(&[
            der::encode_context_primitive(1, b"ops@example.com"),
            der::encode_context_primitive(6, b"https://issuer.example"),
        ])),
    };
    let policy_mappings = RawExtension {
        oid: Oid::new([2, 5, 29, 33]),
        id: ExtensionId::PolicyMappings,
        critical: true,
        value: der::encode_sequence(&der::encode_sequence(&der::concat(&[
            der::encode_oid(&Oid::new([1, 2, 3, 4])),
            der::encode_oid(&Oid::new([1, 2, 3, 5])),
        ]))),
    };
    let policy_constraints = RawExtension {
        oid: Oid::new([2, 5, 29, 36]),
        id: ExtensionId::PolicyConstraints,
        critical: true,
        value: der::encode_sequence(&der::concat(&[
            der::encode_context_primitive(0, &[2]),
            der::encode_context_primitive(1, &[5]),
        ])),
    };
    let inhibit_any_policy = RawExtension {
        oid: Oid::new([2, 5, 29, 54]),
        id: ExtensionId::InhibitAnyPolicy,
        critical: true,
        value: der::encode_integer(4),
    };
    let cert = test_cert_with_extensions(
        vec![
            issuer_alt_name,
            policy_mappings,
            policy_constraints,
            inhibit_any_policy,
        ],
        "fallback.example",
    );

    let issuer_names = cert.issuer_alt_names();
    assert_eq!(issuer_names.len(), 2);
    assert_eq!(issuer_names[0].type_, GeneralNameType::Email);
    assert_eq!(issuer_names[0].value_string(), "ops@example.com");
    assert_eq!(issuer_names[1].type_, GeneralNameType::Uri);

    let mappings = cert.policy_mappings();
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].issuer_domain_policy, vec![1, 2, 3, 4]);
    assert_eq!(mappings[0].subject_domain_policy, vec![1, 2, 3, 5]);

    let constraints = cert.policy_constraints().unwrap();
    assert_eq!(constraints.require_explicit_policy, Some(2));
    assert_eq!(constraints.inhibit_policy_mapping, Some(5));
    assert_eq!(cert.inhibit_any_policy(), Some(4));
}
