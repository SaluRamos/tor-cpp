#include "onion_router_descriptor_parser.h"
#include <sstream>
#include <string>
#include <vector>

// Nota: Você deve plugar aqui sua implementação de decode_base64
// que retorne um buffer de bytes (std::vector<uint8_t> ou similar).

namespace tor {

void onion_router_descriptor_parser::parse(
    onion_router* router,
    std::string_view descriptor
) {
    if (!router) return;

    std::stringstream ss{ std::string(descriptor) };
    std::string line;
    document_location current_location = document_location::control_word;
    std::string current_key_accum;

    while (std::getline(ss, line)) {
        // Limpeza de line endings (\r\n -> \n)
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line.empty()) continue;

        // Extrai o primeiro token para identificar comandos
        std::stringstream line_stream(line);
        std::string first_token;
        line_stream >> first_token;

        // onion-key
        if (line == CW_ONION_KEY) {
            current_location = document_location::onion_key;
            continue;
        }
        // signing-key
        else if (line == CW_SIGNING_KEY) {
            current_location = document_location::signing_key;
            continue;
        }
        // ntor-onion-key [base64]
        else if (first_token == CW_NTOR_ONION_KEY) {
            std::string b64_value;
            if (line_stream >> b64_value) {
                router->set_ntor_onion_key(decode_base64_std(b64_value));
            }
            continue;
        }
        // -----BEGIN RSA PUBLIC KEY-----
        else if (line == CW_KEY_BEGIN) {
            if (current_location == document_location::onion_key) {
                current_location = document_location::onion_key_content;
            }
            else if (current_location == document_location::signing_key) {
                current_location = document_location::signing_key_content;
            }
            current_key_accum.clear();
            continue;
        }
        // -----END RSA PUBLIC KEY-----
        else if (line == CW_KEY_END) {
            if (current_location == document_location::onion_key_content) {
                router->set_onion_key(decode_base64_std(current_key_accum));
            }
            else if (current_location == document_location::signing_key_content) {
                router->set_signing_key(decode_base64_std(current_key_accum));
            }
            current_location = document_location::control_word;
            current_key_accum.clear();
            continue;
        }
        // Acumulação de conteúdo de chave (Base64 em múltiplas linhas)
        else if (current_location == document_location::onion_key_content ||
                 current_location == document_location::signing_key_content) {
            current_key_accum += line;
        }
    }
}

}