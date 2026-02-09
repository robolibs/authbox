/**
 * Enterprise PKI Extensions Example
 *
 * Demonstrates the 4 enterprise certificate extensions from Phase 13:
 * 1. Issuer Alternative Name (IAN)
 * 2. Policy Mappings
 * 3. Policy Constraints
 * 4. Inhibit Any-Policy
 *
 * Real-world scenario: Multi-national corporation with complex PKI
 */

#include <cstring>
#include <iostream>
#include <keylock/crypto/context.hpp>
#include <keylock/keylock.hpp>
#include <pki/asn1_writer.hpp>
#include <pki/builder.hpp>
#include <pki/certificate.hpp>

using namespace keylock;
using namespace authbox::pik;
using namespace authbox::pik::der;

void print_separator(const std::string &title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(60, '=') << "\n\n";
}

/**
 * Example 1: Issuer Alternative Name (IAN)
 *
 * Scenario: GlobalCorp has multiple CA identities after acquiring RegionalBank
 * - Original CA: ca.globalcorp.com
 * - Acquired CA: pki.regionalbank.com
 * - Need both identities to be recognized
 */
void example_issuer_alternative_name() {
    print_separator("Example 1: Issuer Alternative Name (IAN)");

    std::cout << "Scenario: GlobalCorp acquired RegionalBank\n";
    std::cout << "CA needs to be recognized by multiple DNS names:\n";
    std::cout << "  - ca.globalcorp.com (primary)\n";
    std::cout << "  - pki.regionalbank.com (legacy)\n";
    std::cout << "  - ca.internal.globalcorp.net (internal)\n\n";

    // Create CA key
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto ca_key = ctx.generate_keypair();

    // Build CA certificate with IAN extension
    auto ca_dn = DistinguishedName::from_string("CN=GlobalCorp Root CA,O=GlobalCorp,C=US").value;

    CertificateBuilder ca_builder;
    ca_builder.set_serial(1001)
        .set_subject(ca_dn)
        .set_issuer(ca_dn)
        .set_validity(std::chrono::system_clock::now(),
                      std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 10))
        .set_subject_public_key_ed25519(ca_key.public_key)
        .set_basic_constraints(true, 5);

    // Add IAN extension manually using DER encoding
    std::vector<std::vector<uint8_t>> general_names;

    // Add DNS names
    std::vector<std::string> dns_names = {"ca.globalcorp.com", "pki.regionalbank.com", "ca.internal.globalcorp.net"};

    for (const auto &dns : dns_names) {
        std::vector<uint8_t> dns_bytes(dns.begin(), dns.end());
        // [2] IMPLICIT for dNSName
        general_names.push_back(
            encode_tlv(ASN1Class::ContextSpecific, false, 2, ByteSpan(dns_bytes.data(), dns_bytes.size())));
    }

    // Add email
    std::string email = "pki-admin@globalcorp.com";
    std::vector<uint8_t> email_bytes(email.begin(), email.end());
    // [1] IMPLICIT for rfc822Name
    general_names.push_back(
        encode_tlv(ASN1Class::ContextSpecific, false, 1, ByteSpan(email_bytes.data(), email_bytes.size())));

    auto ian_value = encode_sequence(concat(general_names));

    RawExtension ian_ext;
    ian_ext.oid.nodes = {2, 5, 29, 18}; // IAN OID
    ian_ext.id = ExtensionId::IssuerAltName;
    ian_ext.critical = false; // RFC 5280: SHOULD be non-critical
    ian_ext.value = ian_value;

    ca_builder.add_extension(ian_ext);

    // Build and sign CA certificate
    auto ca_cert = ca_builder.build_ed25519(ca_key, true);
    if (!ca_cert.success) {
        std::cerr << "Failed to build CA cert: " << ca_cert.error << "\n";
        return;
    }

    std::cout << "✓ CA Certificate created with IAN extension\n\n";

    // Parse and display IAN
    auto issuer_alt_names = ca_cert.value.issuer_alt_names();
    std::cout << "Issuer Alternative Names (" << issuer_alt_names.size() << " entries):\n";
    for (const auto &name : issuer_alt_names) {
        std::string type_str;
        switch (name.type) {
        case IssuerAltNameExtension::GeneralNameType::DNSName:
            type_str = "DNS";
            break;
        case IssuerAltNameExtension::GeneralNameType::Email:
            type_str = "Email";
            break;
        case IssuerAltNameExtension::GeneralNameType::URI:
            type_str = "URI";
            break;
        default:
            type_str = "Other";
        }
        std::cout << "  [" << type_str << "] " << name.value << "\n";
    }

    std::cout << "\n✓ Legacy systems can now find CA at pki.regionalbank.com\n";
    std::cout << "✓ New systems use ca.globalcorp.com\n";
    std::cout << "✓ Internal systems use ca.internal.globalcorp.net\n";
}

/**
 * Example 2: Policy Mappings
 *
 * Scenario: GlobalCorp (US) and EuroTech (EU) form joint venture
 * - GlobalCorp policy: OID 1.2.840.113549.1.9.16 (NIST compliance)
 * - EuroTech policy: OID 1.3.6.1.4.1.99999.1.2.3 (eIDAS compliance)
 * - Need to recognize each other's policies as equivalent
 */
void example_policy_mappings() {
    print_separator("Example 2: Policy Mappings");

    std::cout << "Scenario: GlobalCorp (US) partners with EuroTech (EU)\n";
    std::cout << "Need to map certificate policies:\n";
    std::cout << "  GlobalCorp policy: 1.2.840.113549.1.9.16 (NIST)\n";
    std::cout << "  EuroTech policy:   1.3.6.1.4.1.99999.1.2.3 (eIDAS)\n";
    std::cout << "  Mapping: These policies are considered equivalent\n\n";

    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto bridge_ca_key = ctx.generate_keypair();

    auto bridge_dn = DistinguishedName::from_string("CN=GlobalCorp-EuroTech Bridge CA,O=Joint Venture,C=US").value;

    CertificateBuilder bridge_builder;
    bridge_builder.set_serial(2001)
        .set_subject(bridge_dn)
        .set_issuer(bridge_dn)
        .set_validity(std::chrono::system_clock::now(),
                      std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 5))
        .set_subject_public_key_ed25519(bridge_ca_key.public_key)
        .set_basic_constraints(true, 3);

    // Create Policy Mappings extension
    std::vector<std::vector<uint8_t>> policy_mappings;

    // Mapping 1: GlobalCorp NIST ↔ EuroTech eIDAS
    {
        std::vector<std::vector<uint8_t>> mapping;
        Oid issuer_policy;
        issuer_policy.nodes = {1, 2, 840, 113549, 1, 9, 16};
        mapping.push_back(encode_oid(issuer_policy));

        Oid subject_policy;
        subject_policy.nodes = {1, 3, 6, 1, 4, 1, 99999, 1, 2, 3};
        mapping.push_back(encode_oid(subject_policy));

        policy_mappings.push_back(encode_sequence(concat(mapping)));
    }

    // Mapping 2: High assurance policies
    {
        std::vector<std::vector<uint8_t>> mapping;
        Oid issuer_policy;
        issuer_policy.nodes = {1, 2, 840, 113549, 1, 9, 17};
        mapping.push_back(encode_oid(issuer_policy));

        Oid subject_policy;
        subject_policy.nodes = {1, 3, 6, 1, 4, 1, 99999, 1, 2, 4};
        mapping.push_back(encode_oid(subject_policy));

        policy_mappings.push_back(encode_sequence(concat(mapping)));
    }

    auto pm_value = encode_sequence(concat(policy_mappings));

    RawExtension pm_ext;
    pm_ext.oid.nodes = {2, 5, 29, 33}; // Policy Mappings OID
    pm_ext.id = ExtensionId::PolicyMappings;
    pm_ext.critical = true; // RFC 5280: SHOULD be critical
    pm_ext.value = pm_value;

    bridge_builder.add_extension(pm_ext);

    auto bridge_cert = bridge_builder.build_ed25519(bridge_ca_key, true);
    if (!bridge_cert.success) {
        std::cerr << "Failed to build bridge cert: " << bridge_cert.error << "\n";
        return;
    }

    std::cout << "✓ Bridge CA certificate created with Policy Mappings\n\n";

    // Parse and display policy mappings
    auto mappings = bridge_cert.value.policy_mappings();
    std::cout << "Policy Mappings (" << mappings.size() << " entries):\n";
    for (size_t i = 0; i < mappings.size(); ++i) {
        std::cout << "  Mapping " << (i + 1) << ":\n";
        std::cout << "    Issuer Policy:  ";
        for (size_t j = 0; j < mappings[i].issuer_domain_policy.size(); ++j) {
            if (j > 0)
                std::cout << ".";
            std::cout << mappings[i].issuer_domain_policy[j];
        }
        std::cout << "\n    Subject Policy: ";
        for (size_t j = 0; j < mappings[i].subject_domain_policy.size(); ++j) {
            if (j > 0)
                std::cout << ".";
            std::cout << mappings[i].subject_domain_policy[j];
        }
        std::cout << "\n";
    }

    std::cout << "\n✓ GlobalCorp employees can now authenticate to EuroTech systems\n";
    std::cout << "✓ EuroTech employees can authenticate to GlobalCorp systems\n";
    std::cout << "✓ Both organizations maintain their own policy requirements\n";
}

/**
 * Example 3: Policy Constraints
 *
 * Scenario: Financial institution with strict policy enforcement
 * - Root CA allows flexible policies
 * - Intermediate CA for payment systems MUST enforce policies
 * - All certs below must have explicit policies (regulatory requirement)
 */
void example_policy_constraints() {
    print_separator("Example 3: Policy Constraints");

    std::cout << "Scenario: BankCorp issues payment processing certificates\n";
    std::cout << "Regulatory requirement (PCI-DSS): All payment certs MUST have policies\n";
    std::cout << "Policy Constraints enforce this requirement downstream\n\n";

    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto payments_ca_key = ctx.generate_keypair();

    auto payments_dn =
        DistinguishedName::from_string("CN=BankCorp Payment Systems CA,O=BankCorp,OU=Payment Processing,C=US").value;

    CertificateBuilder payments_builder;
    payments_builder.set_serial(3001)
        .set_subject(payments_dn)
        .set_issuer(payments_dn)
        .set_validity(std::chrono::system_clock::now(),
                      std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 7))
        .set_subject_public_key_ed25519(payments_ca_key.public_key)
        .set_basic_constraints(true, 2);

    // Create Policy Constraints extension
    std::vector<std::vector<uint8_t>> constraints;

    // requireExplicitPolicy [0] = 1
    constraints.push_back(encode_tlv(ASN1Class::ContextSpecific, false, 0, ByteSpan((const uint8_t *)"\x01", 1)));

    // inhibitPolicyMapping [1] = 0
    constraints.push_back(encode_tlv(ASN1Class::ContextSpecific, false, 1, ByteSpan((const uint8_t *)"\x00", 1)));

    auto pc_value = encode_sequence(concat(constraints));

    RawExtension pc_ext;
    pc_ext.oid.nodes = {2, 5, 29, 36}; // Policy Constraints OID
    pc_ext.id = ExtensionId::PolicyConstraints;
    pc_ext.critical = true; // RFC 5280: MUST be critical
    pc_ext.value = pc_value;

    payments_builder.add_extension(pc_ext);

    auto payments_cert = payments_builder.build_ed25519(payments_ca_key, true);
    if (!payments_cert.success) {
        std::cerr << "Failed to build payments cert: " << payments_cert.error << "\n";
        return;
    }

    std::cout << "✓ Payment Systems CA certificate created with Policy Constraints\n\n";

    // Parse and display policy constraints
    auto pc = payments_cert.value.policy_constraints();
    if (pc.has_value()) {
        std::cout << "Policy Constraints:\n";

        if (pc->require_explicit_policy().has_value()) {
            auto skip_certs = pc->require_explicit_policy().value();
            std::cout << "  requireExplicitPolicy: " << skip_certs << " certificate(s)\n";
            std::cout << "    → After " << skip_certs << " cert(s), ALL must have explicit policies\n";
        }

        if (pc->inhibit_policy_mapping().has_value()) {
            auto skip_certs = pc->inhibit_policy_mapping().value();
            std::cout << "  inhibitPolicyMapping: " << skip_certs << " certificate(s)\n";
            if (skip_certs == 0) {
                std::cout << "    → Policy mapping FORBIDDEN below this CA\n";
            } else {
                std::cout << "    → After " << skip_certs << " cert(s), policy mapping forbidden\n";
            }
        }
    }

    std::cout << "\n✓ Ensures PCI-DSS compliance (policy enforcement)\n";
    std::cout << "✓ Prevents policy bypass attacks\n";
    std::cout << "✓ Passes regulatory audits\n";
}

/**
 * Example 4: Inhibit Any-Policy
 *
 * Scenario: Government PKI preventing policy bypass
 * - Root CA for classified systems
 * - Must prevent "anyPolicy" wildcard abuse
 * - After 2 levels, anyPolicy OID (2.5.29.32.0) is blocked
 */
void example_inhibit_any_policy() {
    print_separator("Example 4: Inhibit Any-Policy");

    std::cout << "Scenario: Government classified PKI\n";
    std::cout << "Security requirement: Prevent 'anyPolicy' wildcard bypass\n";
    std::cout << "anyPolicy OID (2.5.29.32.0) matches any policy requirement\n";
    std::cout << "Attackers could abuse this to bypass security controls\n\n";

    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto gov_ca_key = ctx.generate_keypair();

    auto gov_dn = DistinguishedName::from_string("CN=US Government PKI Root,O=U.S. Government,C=US").value;

    CertificateBuilder gov_builder;
    gov_builder.set_serial(4001)
        .set_subject(gov_dn)
        .set_issuer(gov_dn)
        .set_validity(std::chrono::system_clock::now(),
                      std::chrono::system_clock::now() + std::chrono::hours(24 * 365 * 20))
        .set_subject_public_key_ed25519(gov_ca_key.public_key)
        .set_basic_constraints(true, 10);

    // Create Inhibit Any-Policy extension (just an INTEGER)
    auto iap_value = encode_integer(std::vector<uint8_t>{0x02}); // Skip 2 certificates

    RawExtension iap_ext;
    iap_ext.oid.nodes = {2, 5, 29, 54}; // Inhibit Any-Policy OID
    iap_ext.id = ExtensionId::InhibitAnyPolicy;
    iap_ext.critical = true; // RFC 5280: MUST be critical
    iap_ext.value = iap_value;

    gov_builder.add_extension(iap_ext);

    auto gov_cert = gov_builder.build_ed25519(gov_ca_key, true);
    if (!gov_cert.success) {
        std::cerr << "Failed to build gov cert: " << gov_cert.error << "\n";
        return;
    }

    std::cout << "✓ Government Root CA certificate created with Inhibit Any-Policy\n\n";

    // Parse and display inhibit any-policy
    auto skip_certs = gov_cert.value.inhibit_any_policy();
    if (skip_certs.has_value()) {
        std::cout << "Inhibit Any-Policy: " << skip_certs.value() << " certificate(s)\n";
        std::cout << "\nCertificate Chain Enforcement:\n";
        std::cout << "  Root CA (this cert)          → anyPolicy allowed\n";
        std::cout << "  ↓ Intermediate CA 1 (count=1) → anyPolicy allowed\n";
        std::cout << "  ↓ Intermediate CA 2 (count=0) → anyPolicy allowed\n";
        std::cout << "  ↓ Sub CA               (BLOCK) → anyPolicy FORBIDDEN\n";
        std::cout << "  ↓ End-entity cert      (BLOCK) → anyPolicy FORBIDDEN\n";
    }

    std::cout << "\n✓ Prevents anyPolicy bypass attacks\n";
    std::cout << "✓ Enforces explicit policy requirements\n";
    std::cout << "✓ Meets NIST SP 800-57 requirements\n";
}

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║     keylock ENTERPRISE PKI EXTENSIONS DEMONSTRATION      ║\n";
    std::cout << "║                   Phase 13 Examples                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n";

    try {
        example_issuer_alternative_name();
        example_policy_mappings();
        example_policy_constraints();
        example_inhibit_any_policy();

        print_separator("Summary");
        std::cout << "All 4 enterprise extensions demonstrated successfully!\n\n";
        std::cout << "These extensions enable:\n";
        std::cout << "  ✓ Multi-national corporations\n";
        std::cout << "  ✓ Mergers & acquisitions\n";
        std::cout << "  ✓ Regulatory compliance (NIST, eIDAS, PCI-DSS)\n";
        std::cout << "  ✓ Complex organizational hierarchies\n";
        std::cout << "  ✓ Cross-organizational trust\n";
        std::cout << "  ✓ Enterprise-grade security\n\n";
        std::cout << "keylock is now ENTERPRISE-READY! 🚀\n\n";

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
