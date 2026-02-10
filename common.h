#pragma once

#include <cstdint>
#include <string>
#include <vector>

// O onion_router.h agora deve usar std::string e std::vector conforme as migrações anteriores
#include "onion_router.h"

namespace tor {

// Definições de tipos base do protocolo Tor
using circuit_id_type       = uint32_t;
using circuit_id_v3_type    = uint16_t;
using tor_stream_id_type    = uint16_t;
using payload_size_type     = uint16_t;
using protocol_version_type = uint16_t;

enum class circuit_node_type
{
    normal,
    introduction_point,
};

enum class handshake_type
{
    tap,   // Protocolo antigo (RSA/DH)
    ntor   // Protocolo moderno (Curve25519)
};

// Configuração padrão
static constexpr handshake_type preferred_handshake_type = handshake_type::ntor;

// O onion_router_list que era collections::list agora é um vector de ponteiros
// (ou unique_ptr, dependendo da sua estratégia de ownership)
using onion_router_list = std::vector<onion_router*>;

}