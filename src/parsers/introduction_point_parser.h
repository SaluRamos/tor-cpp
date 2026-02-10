#pragma once

#include <string>
#include <vector>
#include <string_view>

// Mantendo as dependências internas do projeto Tor
#include "../consensus.h"
#include "../onion_router.h"

namespace tor {

struct introduction_point_parser {
    // onion_router_list geralmente é um std::vector de ponteiros ou referências
    onion_router_list introduction_point_list;

    enum class document_location {
        control_word,
        service_key,
        service_key_content,
    };

    // Palavras de controle como constantes de visualização de string
    static constexpr std::string_view CW_INTRO_POINT  = "introduction-point";
    static constexpr std::string_view CW_SERVICE_KEY  = "service-key";
    static constexpr std::string_view CW_KEY_BEGIN    = "-----BEGIN RSA PUBLIC KEY-----";
    static constexpr std::string_view CW_KEY_END      = "-----END RSA PUBLIC KEY-----";

    void parse(
        consensus& consensus_obj,
        std::string_view descriptor
    );
};

}