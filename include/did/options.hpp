#pragma once

namespace authbox::did {

    // Options for DID resolution
    struct ResolveOptions {
        bool require_https{true};
        bool require_matching_id{true};
    };

} // namespace authbox::did
