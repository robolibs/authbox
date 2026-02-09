#include <array>
#include <vector>

#include <doctest/doctest.h>

#include <pki/asn1_utils.hpp>

using namespace authbox::pik;

TEST_SUITE("cert/asn1") {
    TEST_CASE("parse INTEGER") {
        std::array<uint8_t, 3> data{0x02, 0x01, 0x05};
        auto result = parse_integer(ByteSpan(data.data(), data.size()));
        REQUIRE(result.success);
        REQUIRE(result.value.size() == 1);
        CHECK(result.value[0] == 0x05);
    }

    TEST_CASE("parse OBJECT IDENTIFIER") {
        std::array<uint8_t, 5> data{0x06, 0x03, 0x2a, 0x03, 0x04};
        auto result = parse_oid(ByteSpan(data.data(), data.size()));
        REQUIRE(result.success);
        CHECK(result.value.nodes[0] == 1);
        CHECK(result.value.nodes[1] == 2);
    }

    TEST_CASE("parse UTCTime") {
        std::array<uint8_t, 15> data{0x17, 0x0d, '2', '3', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'};
        auto result = parse_utc_time(ByteSpan(data.data(), data.size()));
        CHECK(result.success);
    }
}
