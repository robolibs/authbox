#include <doctest/doctest.h>

#include <authbox.hpp>

TEST_CASE("did parser accepts valid did:web") {
    const auto result = authbox::did::parse("did:web:example.com");
    CHECK(result.is_ok());
    CHECK(result.value().method == "web");
}

TEST_CASE("did parser rejects malformed value") {
    const auto result = authbox::did::parse("https://example.com");
    CHECK(result.is_err());
}
