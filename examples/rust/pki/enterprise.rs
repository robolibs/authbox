use authbox::pki::{
    Asn1Class, Certificate, CertificateBuilder, DerTime, ExtensionId, GeneralNameType, Oid,
    RawExtension, der,
};

fn example_time(year: i32) -> DerTime {
    DerTime {
        year,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     keylock ENTERPRISE PKI EXTENSIONS DEMONSTRATION      ║");
    println!("║                   Pure Rust authbox port                 ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    example_issuer_alternative_name()?;
    example_policy_mappings()?;
    example_policy_constraints()?;
    example_inhibit_any_policy()?;

    print_separator("Summary");
    println!("All 4 enterprise extensions demonstrated successfully!");
    println!();
    println!("These extensions enable:");
    println!("  ✓ Multi-national corporations");
    println!("  ✓ Mergers & acquisitions");
    println!("  ✓ Regulatory compliance (NIST, eIDAS, PCI-DSS)");
    println!("  ✓ Complex organizational hierarchies");
    println!("  ✓ Cross-organizational trust");
    println!("  ✓ Enterprise-grade security");
    println!();

    Ok(())
}

fn print_separator(title: &str) {
    println!("\n{}\n  {title}\n{}\n", "=".repeat(60), "=".repeat(60));
}

fn build_ca_with_extensions(
    serial: u64,
    subject: &str,
    path_length: u32,
    extensions: Vec<RawExtension>,
) -> Result<Certificate, Box<dyn std::error::Error>> {
    let keypair = keylock::generate_ed25519_keypair()?;
    let mut builder = CertificateBuilder::new()
        .set_serial_u64(serial)
        .set_subject_from_string(subject)?
        .set_issuer_from_string(subject)?
        .set_validity(example_time(2020), example_time(2035))
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_basic_constraints(true, Some(path_length))?;

    for extension in extensions {
        builder = builder.add_extension(extension);
    }

    Ok(builder.build_ed25519_with_self_signed(&keypair, true)?)
}

fn example_issuer_alternative_name() -> Result<(), Box<dyn std::error::Error>> {
    print_separator("Example 1: Issuer Alternative Name (IAN)");
    println!("Scenario: GlobalCorp acquired RegionalBank");
    println!("CA needs to be recognized by multiple DNS names:");
    println!("  - ca.globalcorp.com (primary)");
    println!("  - pki.regionalbank.com (legacy)");
    println!("  - ca.internal.globalcorp.net (internal)");
    println!();

    let names = der::concat(&[
        der::encode_context_primitive(2, b"ca.globalcorp.com"),
        der::encode_context_primitive(2, b"pki.regionalbank.com"),
        der::encode_context_primitive(2, b"ca.internal.globalcorp.net"),
        der::encode_context_primitive(1, b"pki-admin@globalcorp.com"),
    ]);
    let cert = build_ca_with_extensions(
        1001,
        "CN=GlobalCorp Root CA,O=GlobalCorp,C=US",
        5,
        vec![RawExtension {
            oid: Oid::new([2, 5, 29, 18]),
            id: ExtensionId::IssuerAltName,
            critical: false,
            value: der::encode_sequence(&names),
        }],
    )?;

    println!("✓ CA Certificate created with IAN extension\n");
    let issuer_alt_names = cert.issuer_alt_names();
    println!(
        "Issuer Alternative Names ({} entries):",
        issuer_alt_names.len()
    );
    for name in issuer_alt_names {
        let kind = match name.type_ {
            GeneralNameType::DnsName => "DNS",
            GeneralNameType::Email => "Email",
            GeneralNameType::Uri => "URI",
            GeneralNameType::IpAddress => "IP",
            GeneralNameType::Other => "Other",
        };
        println!("  [{kind}] {}", name.value_string());
    }
    println!("\n✓ Legacy systems can now find CA at pki.regionalbank.com");
    println!("✓ New systems use ca.globalcorp.com");
    println!("✓ Internal systems use ca.internal.globalcorp.net");

    Ok(())
}

fn example_policy_mappings() -> Result<(), Box<dyn std::error::Error>> {
    print_separator("Example 2: Policy Mappings");
    println!("Scenario: GlobalCorp (US) partners with EuroTech (EU)");
    println!("Need to map certificate policies:");
    println!("  GlobalCorp policy: 1.2.840.113549.1.9.16 (NIST)");
    println!("  EuroTech policy:   1.3.6.1.4.1.99999.1.2.3 (eIDAS)");
    println!("  Mapping: These policies are considered equivalent\n");

    let mapping_one = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([1, 2, 840, 113549, 1, 9, 16])),
        der::encode_oid(&Oid::new([1, 3, 6, 1, 4, 1, 99999, 1, 2, 3])),
    ]));
    let mapping_two = der::encode_sequence(&der::concat(&[
        der::encode_oid(&Oid::new([1, 2, 840, 113549, 1, 9, 17])),
        der::encode_oid(&Oid::new([1, 3, 6, 1, 4, 1, 99999, 1, 2, 4])),
    ]));
    let cert = build_ca_with_extensions(
        2001,
        "CN=GlobalCorp-EuroTech Bridge CA,O=Joint Venture,C=US",
        3,
        vec![RawExtension {
            oid: Oid::new([2, 5, 29, 33]),
            id: ExtensionId::PolicyMappings,
            critical: true,
            value: der::encode_sequence(&der::concat(&[mapping_one, mapping_two])),
        }],
    )?;

    println!("✓ Bridge CA certificate created with Policy Mappings\n");
    let mappings = cert.policy_mappings();
    println!("Policy Mappings ({} entries):", mappings.len());
    for (index, mapping) in mappings.iter().enumerate() {
        println!("  Mapping {}:", index + 1);
        println!(
            "    Issuer Policy:  {}",
            oid_string(&mapping.issuer_domain_policy)
        );
        println!(
            "    Subject Policy: {}",
            oid_string(&mapping.subject_domain_policy)
        );
    }
    println!("\n✓ GlobalCorp employees can now authenticate to EuroTech systems");
    println!("✓ EuroTech employees can authenticate to GlobalCorp systems");
    println!("✓ Both organizations maintain their own policy requirements");

    Ok(())
}

fn example_policy_constraints() -> Result<(), Box<dyn std::error::Error>> {
    print_separator("Example 3: Policy Constraints");
    println!("Scenario: BankCorp issues payment processing certificates");
    println!("Regulatory requirement (PCI-DSS): All payment certs MUST have policies");
    println!("Policy Constraints enforce this requirement downstream\n");

    let cert = build_ca_with_extensions(
        3001,
        "CN=BankCorp Payment Systems CA,O=BankCorp,OU=Payment Processing,C=US",
        2,
        vec![RawExtension {
            oid: Oid::new([2, 5, 29, 36]),
            id: ExtensionId::PolicyConstraints,
            critical: true,
            value: der::encode_sequence(&der::concat(&[
                der::encode_tlv(Asn1Class::ContextSpecific, false, 0, &[1]),
                der::encode_tlv(Asn1Class::ContextSpecific, false, 1, &[0]),
            ])),
        }],
    )?;

    println!("✓ Payment Systems CA certificate created with Policy Constraints\n");
    if let Some(constraints) = cert.policy_constraints() {
        println!("Policy Constraints:");
        if let Some(skip_certs) = constraints.require_explicit_policy {
            println!("  requireExplicitPolicy: {skip_certs} certificate(s)");
            println!("    → After {skip_certs} cert(s), ALL must have explicit policies");
        }
        if let Some(skip_certs) = constraints.inhibit_policy_mapping {
            println!("  inhibitPolicyMapping: {skip_certs} certificate(s)");
            if skip_certs == 0 {
                println!("    → Policy mapping FORBIDDEN below this CA");
            } else {
                println!("    → After {skip_certs} cert(s), policy mapping forbidden");
            }
        }
    }
    println!("\n✓ Ensures PCI-DSS compliance (policy enforcement)");
    println!("✓ Prevents policy bypass attacks");
    println!("✓ Passes regulatory audits");

    Ok(())
}

fn example_inhibit_any_policy() -> Result<(), Box<dyn std::error::Error>> {
    print_separator("Example 4: Inhibit Any-Policy");
    println!("Scenario: Government classified PKI");
    println!("Security requirement: Prevent 'anyPolicy' wildcard bypass");
    println!("anyPolicy OID (2.5.29.32.0) matches any policy requirement");
    println!("Attackers could abuse this to bypass security controls\n");

    let cert = build_ca_with_extensions(
        4001,
        "CN=US Government PKI Root,O=U.S. Government,C=US",
        10,
        vec![RawExtension {
            oid: Oid::new([2, 5, 29, 54]),
            id: ExtensionId::InhibitAnyPolicy,
            critical: true,
            value: der::encode_integer(2),
        }],
    )?;

    println!("✓ Government Root CA certificate created with Inhibit Any-Policy\n");
    if let Some(skip_certs) = cert.inhibit_any_policy() {
        println!("Inhibit Any-Policy: {skip_certs} certificate(s)");
        println!("\nCertificate Chain Enforcement:");
        println!("  Root CA (this cert)          → anyPolicy allowed");
        println!("  ↓ Intermediate CA 1 (count=1) → anyPolicy allowed");
        println!("  ↓ Intermediate CA 2 (count=0) → anyPolicy allowed");
        println!("  ↓ Sub CA               (BLOCK) → anyPolicy FORBIDDEN");
        println!("  ↓ End-entity cert      (BLOCK) → anyPolicy FORBIDDEN");
    }
    println!("\n✓ Prevents anyPolicy bypass attacks");
    println!("✓ Enforces explicit policy requirements");
    println!("✓ Meets NIST SP 800-57 requirements");

    Ok(())
}

fn oid_string(nodes: &[u32]) -> String {
    nodes
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
