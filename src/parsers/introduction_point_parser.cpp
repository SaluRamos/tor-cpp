#include "introduction_point_parser.h"
#include <sstream>

// Nota: Você deve substituir as chamadas de decode abaixo pelas 
// funções equivalentes da sua biblioteca de criptografia (OpenSSL, etc) 
// ou helpers que utilizem a CRT padrão.

namespace tor {

void introduction_point_parser::parse(
    consensus& consensus_obj,
    std::string_view descriptor
) {
    std::stringstream ss{ std::string(descriptor) };
    std::string line;
    
    document_location current_location = document_location::control_word;
    onion_router* current_router = nullptr;
    std::string current_key_base64;

    while (std::getline(ss, line)) {
        // Normalização de line endings (remover \r se presente)
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) continue;

        // Tokenização simples da linha
        std::stringstream line_stream(line);
        std::string first_token;
        line_stream >> first_token;

        // 1. introduction-point [ID]
        if (first_token == CW_INTRO_POINT) {
            std::string identity_b32;
            if (line_stream >> identity_b32) {
                // Substitua pelo seu decoder Base32 padrão
                auto identity_fingerprint = decode_base32_std(identity_b32);
                current_router = consensus_obj.get_onion_router_by_identity_fingerprint(identity_fingerprint);
            }
            continue;
        }
        
        // 2. service-key
        else if (first_token == CW_SERVICE_KEY) {
            current_location = document_location::service_key;
            continue;
        }
        
        // 3. -----BEGIN RSA PUBLIC KEY-----
        else if (line == CW_KEY_BEGIN && current_location == document_location::service_key) {
            current_location = document_location::service_key_content;
            current_key_base64.clear();
            continue;
        }
        
        // 4. -----END RSA PUBLIC KEY-----
        else if (line == CW_KEY_END && current_location == document_location::service_key_content) {
            if (current_router) {
                // Substitua pelo seu decoder Base64 padrão
                auto decoded_key = decode_base64_std(current_key_base64);
                current_router->set_service_key(decoded_key);
                
                // Adiciona à lista (assumindo que introduction_point_list é std::vector ou similar)
                introduction_point_list.push_back(current_router);
            }

            current_location = document_location::control_word;
            continue;
        }
        
        // 5. Acúmulo do conteúdo da chave
        else if (current_location == document_location::service_key_content) {
            current_key_base64 += line;
        }
    }
}

}