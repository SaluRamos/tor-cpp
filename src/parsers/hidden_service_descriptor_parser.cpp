#include "hidden_service_descriptor_parser.h"
#include <sstream>
#include <algorithm>

// Nota: Como a mini::crypto::base64 foi removida, 
// você precisará de um substituto para o decode.
// Se você não tiver um, pode usar uma implementação simples de Base64 ou OpenSSL.

namespace mini::tor {

void hidden_service_descriptor_parser::parse(
    consensus& consensus_obj,
    std::string_view descriptor
) {
    std::stringstream ss{ std::string(descriptor) };
    std::string line;
    std::string current_message;
    document_location current_location = document_location::control_word;

    while (std::getline(ss, line)) {
        // Remove \r se o arquivo vier com line endings de Windows
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line == CW_INTRO_POINTS) {
            current_location = document_location::introduction_points;
            continue;
        }
        else if (line == CW_MESSAGE_BEGIN) {
            current_location = document_location::introduction_points_content;
            continue;
        }
        else if (line == CW_MESSAGE_END) {
            current_location = document_location::control_word;
            break; // Encontrou o fim da mensagem, pode parar o loop
        }
        else if (current_location == document_location::introduction_points_content) {
            current_message += line;
        }
    }

    if (current_message.empty()) {
        return;
    }

    // --- Decodificação Base64 ---
    // Substituindo mini::crypto::base64::decode por uma chamada hipotética da CRT/Standard.
    // Você deve plugar aqui sua função de decode (ex: base64_decode do OpenSSL ou similar).
    std::vector<uint8_t> decoded_data = decode_base64_std(current_message);

    // Converte os bytes decodificados de volta para string para o próximo parser
    std::string intro_point_str(
        reinterpret_cast<char*>(decoded_data.data()), 
        decoded_data.size()
    );

    // --- Parse do descritor de introduction points ---
    introduction_point_parser parser;
    parser.parse(consensus_obj, intro_point_str);

    // Transfere a lista para este objeto
    introduction_point_list = std::move(parser.introduction_point_list);
}

} // namespace mini::tor