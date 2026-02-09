#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <keylock/hash/context.hpp>

namespace authbox::pik {

    constexpr inline size_t ASN1_MAX_TAG_NUMBER = (1U << 28); // Guardrail for corrupted tags

    enum class ASN1Class : uint8_t { Universal = 0x00, Application = 0x40, ContextSpecific = 0x80, Private = 0xC0 };

    enum class ASN1Tag : uint8_t {
        EndOfContent = 0x00,
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        ObjectDescriptor = 0x07,
        External = 0x08,
        Real = 0x09,
        Enumerated = 0x0A,
        EmbeddedPdv = 0x0B,
        UTF8String = 0x0C,
        RelativeOID = 0x0D,
        Sequence = 0x10,
        Set = 0x11,
        NumericString = 0x12,
        PrintableString = 0x13,
        T61String = 0x14,
        VideotexString = 0x15,
        IA5String = 0x16,
        UTCTime = 0x17,
        GeneralizedTime = 0x18,
        GraphicString = 0x19,
        VisibleString = 0x1A,
        GeneralString = 0x1B,
        UniversalString = 0x1C,
        CharacterString = 0x1D,
        BMPString = 0x1E
    };

    struct ASN1Identifier {
        ASN1Class tag_class{};
        bool constructed{};
        uint32_t tag_number{};
    };

    enum class SignatureAlgorithmId {
        Unknown = 0,
        RsaPkcs1Sha256,
        RsaPkcs1Sha384,
        RsaPkcs1Sha512,
        RsaPssSha256,
        RsaPssSha384,
        RsaPssSha512,
        EcdsaSha256,
        EcdsaSha384,
        EcdsaSha512,
        Ed25519,
        Ed448
    };

    enum class CurveId { Unknown = 0, Secp256r1, Secp384r1, Secp521r1, Secp256k1, Ed25519, Ed448, X25519, X448 };

    enum class ExtensionId {
        Unknown = 0,
        BasicConstraints,
        KeyUsage,
        ExtendedKeyUsage,
        SubjectAltName,
        AuthorityKeyIdentifier,
        SubjectKeyIdentifier,
        CertificatePolicies,
        CRLDistributionPoints,
        AuthorityInfoAccess,
        NameConstraints,
        // Enterprise extensions (Phase 13)
        IssuerAltName,     // 2.5.29.18
        PolicyMappings,    // 2.5.29.33
        PolicyConstraints, // 2.5.29.36
        InhibitAnyPolicy   // 2.5.29.54
    };

    // CRL Entry Extension IDs (extensions within revoked certificate entries)
    enum class CrlEntryExtensionId {
        Unknown = 0,
        ReasonCode,       // 2.5.29.21
        InvalidityDate,   // 2.5.29.24
        CertificateIssuer // 2.5.29.29
    };

    // CRL Extension IDs (extensions at CRL level)
    enum class CrlExtensionId {
        Unknown = 0,
        AuthorityKeyIdentifier,   // 2.5.29.35
        IssuerAltName,            // 2.5.29.18
        CRLNumber,                // 2.5.29.20
        DeltaCRLIndicator,        // 2.5.29.27
        IssuingDistributionPoint, // 2.5.29.28
        FreshestCRL,              // 2.5.29.46
        AuthorityInfoAccess,      // 1.3.6.1.5.5.7.1.1
        ExpiredCertsOnCRL         // 2.5.29.60
    };

    struct Oid {
        std::vector<uint32_t> nodes;
    };

    struct AlgorithmIdentifier {
        SignatureAlgorithmId signature{};
        keylock::hash::Algorithm hash{keylock::hash::Algorithm::SHA256};
        CurveId curve{CurveId::Unknown};
    };

    struct SubjectPublicKeyInfo {
        AlgorithmIdentifier algorithm{};
        std::vector<uint8_t> public_key;
        uint8_t unused_bits{};
    };

    struct RawExtension {
        Oid oid{};
        ExtensionId id{ExtensionId::Unknown};
        bool critical{};
        std::vector<uint8_t> value;
    };

} // namespace authbox::pik
