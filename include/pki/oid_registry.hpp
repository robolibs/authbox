#pragma once

#include <array>
#include <optional>
#include <span>
#include <utility>

#include <pki/asn1_common.hpp>

namespace authbox::pik {

    /**
     * RFC-defined object identifiers that we care about for certificates.
     * Provides helpers to translate parsed OIDs into strongly typed enums.
     */

    namespace detail {

        template <size_t N> using OidArray = std::array<uint32_t, N>;

        template <typename Enum, size_t N>
        inline Enum lookup_enum(const Oid &oid, const std::array<std::pair<Enum, std::span<const uint32_t>>, N> &table,
                                Enum unknown) {
            for (const auto &[value, pattern] : table) {
                if (oid.nodes.size() != pattern.size()) {
                    continue;
                }
                bool match = true;
                for (size_t i = 0; i < pattern.size(); ++i) {
                    if (oid.nodes[i] != pattern[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return value;
                }
            }
            return unknown;
        }

        inline constexpr OidArray<7> kOidSha256WithRsa{1, 2, 840, 113549, 1, 1, 11};
        inline constexpr OidArray<7> kOidSha384WithRsa{1, 2, 840, 113549, 1, 1, 12};
        inline constexpr OidArray<7> kOidSha512WithRsa{1, 2, 840, 113549, 1, 1, 13};
        inline constexpr OidArray<7> kOidRsaPss{1, 2, 840, 113549, 1, 1, 10};
        inline constexpr OidArray<7> kOidEcdsaSha256{1, 2, 840, 10045, 4, 3, 2};
        inline constexpr OidArray<7> kOidEcdsaSha384{1, 2, 840, 10045, 4, 3, 3};
        inline constexpr OidArray<7> kOidEcdsaSha512{1, 2, 840, 10045, 4, 3, 4};
        inline constexpr OidArray<4> kOidEd25519{1, 3, 101, 112};
        inline constexpr OidArray<4> kOidEd448{1, 3, 101, 113};

        inline const std::array<std::pair<SignatureAlgorithmId, std::span<const uint32_t>>, 9> kSignatureAlgorithms = {
            std::pair{SignatureAlgorithmId::RsaPkcs1Sha256, std::span<const uint32_t>(kOidSha256WithRsa)},
            std::pair{SignatureAlgorithmId::RsaPkcs1Sha384, std::span<const uint32_t>(kOidSha384WithRsa)},
            std::pair{SignatureAlgorithmId::RsaPkcs1Sha512, std::span<const uint32_t>(kOidSha512WithRsa)},
            std::pair{SignatureAlgorithmId::RsaPssSha256, std::span<const uint32_t>(kOidRsaPss)},
            std::pair{SignatureAlgorithmId::EcdsaSha256, std::span<const uint32_t>(kOidEcdsaSha256)},
            std::pair{SignatureAlgorithmId::EcdsaSha384, std::span<const uint32_t>(kOidEcdsaSha384)},
            std::pair{SignatureAlgorithmId::EcdsaSha512, std::span<const uint32_t>(kOidEcdsaSha512)},
            std::pair{SignatureAlgorithmId::Ed25519, std::span<const uint32_t>(kOidEd25519)},
            std::pair{SignatureAlgorithmId::Ed448, std::span<const uint32_t>(kOidEd448)},
        };

        inline constexpr OidArray<9> kOidSha256{2, 16, 840, 1, 101, 3, 4, 2, 1};
        inline constexpr OidArray<9> kOidSha512{2, 16, 840, 1, 101, 3, 4, 2, 3};
        inline constexpr OidArray<11> kOidBlake2b{1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 8};

        inline const std::array<std::pair<keylock::hash::Algorithm, std::span<const uint32_t>>, 3> kHashAlgorithms = {
            std::pair{keylock::hash::Algorithm::SHA256, std::span<const uint32_t>(kOidSha256)},
            std::pair{keylock::hash::Algorithm::SHA512, std::span<const uint32_t>(kOidSha512)},
            std::pair{keylock::hash::Algorithm::BLAKE2b, std::span<const uint32_t>(kOidBlake2b)},
        };

        inline constexpr OidArray<7> kOidSecp256r1{1, 2, 840, 10045, 3, 1, 7};
        inline constexpr OidArray<5> kOidSecp384r1{1, 3, 132, 0, 34};
        inline constexpr OidArray<5> kOidSecp521r1{1, 3, 132, 0, 35};
        inline constexpr OidArray<5> kOidSecp256k1{1, 3, 132, 0, 10};
        inline constexpr OidArray<4> kOidX25519{1, 3, 101, 110};
        inline constexpr OidArray<4> kOidX448{1, 3, 101, 111};

        inline const std::array<std::pair<CurveId, std::span<const uint32_t>>, 8> kCurveOids = {
            std::pair{CurveId::Secp256r1, std::span<const uint32_t>(kOidSecp256r1)},
            std::pair{CurveId::Secp384r1, std::span<const uint32_t>(kOidSecp384r1)},
            std::pair{CurveId::Secp521r1, std::span<const uint32_t>(kOidSecp521r1)},
            std::pair{CurveId::Secp256k1, std::span<const uint32_t>(kOidSecp256k1)},
            std::pair{CurveId::Ed25519, std::span<const uint32_t>(kOidEd25519)},
            std::pair{CurveId::Ed448, std::span<const uint32_t>(kOidEd448)},
            std::pair{CurveId::X25519, std::span<const uint32_t>(kOidX25519)},
            std::pair{CurveId::X448, std::span<const uint32_t>(kOidX448)},
        };

        inline constexpr OidArray<4> kOidBasicConstraints{2, 5, 29, 19};
        inline constexpr OidArray<4> kOidKeyUsage{2, 5, 29, 15};
        inline constexpr OidArray<4> kOidExtendedKeyUsage{2, 5, 29, 37};
        inline constexpr OidArray<4> kOidSubjectAltName{2, 5, 29, 17};
        inline constexpr OidArray<4> kOidAuthorityKeyId{2, 5, 29, 35};
        inline constexpr OidArray<4> kOidSubjectKeyId{2, 5, 29, 14};
        inline constexpr OidArray<4> kOidCertificatePolicies{2, 5, 29, 32};
        inline constexpr OidArray<4> kOidCrlDistributionPoints{2, 5, 29, 31};
        inline constexpr OidArray<9> kOidAuthorityInfoAccess{1, 3, 6, 1, 5, 5, 7, 1, 1};
        inline constexpr OidArray<4> kOidNameConstraints{2, 5, 29, 30};
        // Enterprise extensions (Phase 13)
        inline constexpr OidArray<4> kOidIssuerAltName{2, 5, 29, 18};
        inline constexpr OidArray<4> kOidPolicyMappings{2, 5, 29, 33};
        inline constexpr OidArray<4> kOidPolicyConstraints{2, 5, 29, 36};
        inline constexpr OidArray<4> kOidInhibitAnyPolicy{2, 5, 29, 54};

        inline const std::array<std::pair<ExtensionId, std::span<const uint32_t>>, 14> kExtensionOids = {
            std::pair{ExtensionId::BasicConstraints, std::span<const uint32_t>(kOidBasicConstraints)},
            std::pair{ExtensionId::KeyUsage, std::span<const uint32_t>(kOidKeyUsage)},
            std::pair{ExtensionId::ExtendedKeyUsage, std::span<const uint32_t>(kOidExtendedKeyUsage)},
            std::pair{ExtensionId::SubjectAltName, std::span<const uint32_t>(kOidSubjectAltName)},
            std::pair{ExtensionId::AuthorityKeyIdentifier, std::span<const uint32_t>(kOidAuthorityKeyId)},
            std::pair{ExtensionId::SubjectKeyIdentifier, std::span<const uint32_t>(kOidSubjectKeyId)},
            std::pair{ExtensionId::CertificatePolicies, std::span<const uint32_t>(kOidCertificatePolicies)},
            std::pair{ExtensionId::CRLDistributionPoints, std::span<const uint32_t>(kOidCrlDistributionPoints)},
            std::pair{ExtensionId::AuthorityInfoAccess, std::span<const uint32_t>(kOidAuthorityInfoAccess)},
            std::pair{ExtensionId::NameConstraints, std::span<const uint32_t>(kOidNameConstraints)},
            // Enterprise extensions (Phase 13)
            std::pair{ExtensionId::IssuerAltName, std::span<const uint32_t>(kOidIssuerAltName)},
            std::pair{ExtensionId::PolicyMappings, std::span<const uint32_t>(kOidPolicyMappings)},
            std::pair{ExtensionId::PolicyConstraints, std::span<const uint32_t>(kOidPolicyConstraints)},
            std::pair{ExtensionId::InhibitAnyPolicy, std::span<const uint32_t>(kOidInhibitAnyPolicy)},
        };

    } // namespace detail

    inline SignatureAlgorithmId find_sig_alg_by_oid(const Oid &oid) {
        return detail::lookup_enum(oid, detail::kSignatureAlgorithms, SignatureAlgorithmId::Unknown);
    }

    inline std::optional<keylock::hash::Algorithm> find_hash_by_oid(const Oid &oid) {
        for (const auto &[value, pattern] : detail::kHashAlgorithms) {
            if (oid.nodes.size() != pattern.size()) {
                continue;
            }
            bool match = true;
            for (size_t i = 0; i < pattern.size(); ++i) {
                if (oid.nodes[i] != pattern[i]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return value;
            }
        }
        return std::nullopt;
    }

    inline CurveId find_curve_by_oid(const Oid &oid) {
        return detail::lookup_enum(oid, detail::kCurveOids, CurveId::Unknown);
    }

    inline ExtensionId find_extension_by_oid(const Oid &oid) {
        return detail::lookup_enum(oid, detail::kExtensionOids, ExtensionId::Unknown);
    }

    inline std::optional<Oid> oid_for_signature(SignatureAlgorithmId id) {
        for (const auto &[value, pattern] : detail::kSignatureAlgorithms) {
            if (value == id) {
                return Oid{std::vector<uint32_t>(pattern.begin(), pattern.end())};
            }
        }
        return std::nullopt;
    }

    inline std::optional<Oid> oid_for_curve(CurveId id) {
        for (const auto &[value, pattern] : detail::kCurveOids) {
            if (value == id) {
                return Oid{std::vector<uint32_t>(pattern.begin(), pattern.end())};
            }
        }
        return std::nullopt;
    }

    inline std::optional<Oid> oid_for_extension(ExtensionId id) {
        for (const auto &[value, pattern] : detail::kExtensionOids) {
            if (value == id) {
                return Oid{std::vector<uint32_t>(pattern.begin(), pattern.end())};
            }
        }
        return std::nullopt;
    }

    inline std::optional<Oid> oid_for_hash(keylock::hash::Algorithm algorithm) {
        for (const auto &[value, pattern] : detail::kHashAlgorithms) {
            if (value == algorithm) {
                return Oid{std::vector<uint32_t>(pattern.begin(), pattern.end())};
            }
        }
        return std::nullopt;
    }

} // namespace authbox::pik
