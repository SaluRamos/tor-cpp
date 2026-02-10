#pragma once

#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <memory>
#include <string_view>

// Assumindo que estas classes ainda existem no seu namespace mini::tor
// mas agora usam tipos padrão internamente.
#include "../consensus.h"

namespace mini::tor {

class consensus_parser {
public:
    enum class document_location {
        preamble,
        router_status_entry,
        directory_footer,
    };

    // Definições de controle baseadas no dir-spec.txt
    static constexpr std::string_view PREAMBLE_VALID_UNTIL = "valid-until";
    static constexpr std::string_view FOOTER_START = "directory-footer";

    // Índices para a linha 'r' (router)
    enum router_status_r_idx {
        r_nickname = 1,
        r_identity = 2,
        r_digest = 3,
        r_pub_date = 4,
        r_pub_time = 5,
        r_ip = 6,
        r_or_port = 7,
        r_dir_port = 8,
        r_min_count = 9
    };

    // Flags de status suportadas
    static const std::vector<std::pair<std::string, onion_router::status_flag>> status_flag_map;

    // Métodos Principais
    onion_router::status_flags string_to_status_flags(const std::vector<std::string>& tokens);

    void parse(
        consensus& consensus_obj,
        std::string_view content,
        bool reject_invalid = true
    );

private:
    std::vector<std::string> split(std::string_view s, char delimiter);
};

}