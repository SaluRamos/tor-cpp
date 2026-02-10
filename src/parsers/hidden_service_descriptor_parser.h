#pragma once

#include <string>
#include <vector>
#include <string_view>

// Mantendo as inclusões do domínio Tor
#include "../consensus.h"
#include "introduction_point_parser.h"

namespace tor {

struct hidden_service_descriptor_parser {
    // onion_router_list assume-se ser um std::vector ou similar definido em consensus.h
    onion_router_list introduction_point_list;

    enum class document_location {
        control_word,
        introduction_points,
        introduction_points_content,
    };

    // Palavras de controle como constantes de string_view para eficiência
    static constexpr std::string_view CW_INTRO_POINTS  = "introduction-points";
    static constexpr std::string_view CW_MESSAGE_BEGIN = "-----BEGIN MESSAGE-----";
    static constexpr std::string_view CW_MESSAGE_END   = "-----END MESSAGE-----";

    void parse(
        consensus& consensus_obj,
        std::string_view descriptor
    );
};

}