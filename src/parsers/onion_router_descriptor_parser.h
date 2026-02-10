#pragma once

#include <string>
#include <vector>
#include <string_view>

// Mantendo a dependência do domínio Tor
#include "../onion_router.h"

namespace mini::tor {

struct onion_router_descriptor_parser {
    enum class document_location {
        control_word,

        onion_key,
        onion_key_content,

        signing_key,
        signing_key_content,

        ntor_onion_key,
    };

    // Palavras de controle como constantes para comparação direta
    static constexpr std::string_view CW_ONION_KEY       = "onion-key";
    static constexpr std::string_view CW_SIGNING_KEY     = "signing-key";
    static constexpr std::string_view CW_KEY_BEGIN       = "-----BEGIN RSA PUBLIC KEY-----";
    static constexpr std::string_view CW_KEY_END         = "-----END RSA PUBLIC KEY-----";
    static constexpr std::string_view CW_NTOR_ONION_KEY  = "ntor-onion-key";

    void parse(
        onion_router* router,
        std::string_view descriptor
    );
};

} // namespace mini::tor