#include "consensus_parser.h"
#include <sstream>
#include <algorithm>
#include <iostream>

// Se precisar de base64 ou conversões específicas que eram da mini:
// #include <boost/beast/core/detail/base64.hpp> ou similar. 
// Abaixo assumirei que você tem um helper para o decode.

namespace mini::tor {

const std::vector<std::pair<std::string, onion_router::status_flag>> consensus_parser::status_flag_map = {
    {"Authority", onion_router::status_flag::authority},
    {"BadExit",   onion_router::status_flag::bad_exit},
    {"Exit",      onion_router::status_flag::exit},
    {"Fast",      onion_router::status_flag::fast},
    {"Guard",     onion_router::status_flag::guard},
    {"HSDir",     onion_router::status_flag::hsdir},
    {"Named",     onion_router::status_flag::named},
    {"Stable",    onion_router::status_flag::stable},
    {"Running",   onion_router::status_flag::running},
    {"Unnamed",   onion_router::status_flag::unnamed},
    {"Valid",     onion_router::status_flag::valid},
    {"V2Dir",     onion_router::status_flag::v2dir}
};

std::vector<std::string> consensus_parser::split(std::string_view s, char delimiter) {
    std::vector<std::string> tokens;
    std::string item;
    std::stringstream ss((std::string(s)));
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) tokens.push_back(item);
    }
    return tokens;
}

onion_router::status_flags consensus_parser::string_to_status_flags(const std::vector<std::string>& tokens) {
    onion_router::status_flags result = onion_router::status_flag::none;

    for (const auto& token : tokens) {
        for (const auto& [name, flag] : status_flag_map) {
            if (token == name) {
                result |= flag;
                break;
            }
        }
    }
    return result;
}

void consensus_parser::parse(consensus& consensus_obj, std::string_view content, bool reject_invalid) {
    std::stringstream ss((std::string(content)));
    std::string line;
    document_location current_location = document_location::preamble;
    onion_router* current_router = nullptr;

    while (std::getline(ss, line)) {
        if (line.empty()) continue;

        auto tokens = split(line, ' ');
        if (tokens.empty()) continue;

        // Transição de estado baseada no primeiro caractere ou palavra
        if (tokens[0] == "r") {
            current_location = document_location::router_status_entry;
        } else if (tokens[0] == PREAMBLE_VALID_UNTIL) {
            current_location = document_location::preamble;
        } else if (tokens[0] == FOOTER_START) {
            break; // Fim do parsing útil
        }

        switch (current_location) {
            case document_location::preamble: {
                if (tokens[0] == PREAMBLE_VALID_UNTIL && tokens.size() >= 3) {
                    std::string date_str = tokens[1] + " " + tokens[2];
                    consensus_obj._valid_until.parse(date_str);

                    // Verifica se o consenso expirou usando chrono
                    if (reject_invalid && consensus_obj._valid_until < std::chrono::system_clock::now()) {
                        return;
                    }
                }
                break;
            }

            case document_location::router_status_entry: {
                if (tokens[0] == "r") {
                    if (tokens.size() < r_min_count) continue;

                    // Substitua pela sua função de decode de base64 preferida (ex: OpenSSL, Crypto++, WinAPI)
                    auto identity_fingerprint = decode_base64_std(tokens[r_identity]);

                    current_router = new onion_router(
                        consensus_obj,
                        tokens[r_nickname],
                        tokens[r_ip],
                        static_cast<uint16_t>(std::stoi(tokens[r_or_port])),
                        static_cast<uint16_t>(std::stoi(tokens[r_dir_port])),
                        identity_fingerprint
                    );

                    consensus_obj._onion_router_map.insert({identity_fingerprint, current_router});
                } 
                else if (tokens[0] == "s") {
                    if (current_router) {
                        current_router->set_flags(string_to_status_flags(tokens));
                    }
                }
                break;
            }
            
            default:
                break;
        }
    }
}

} // namespace mini::tor