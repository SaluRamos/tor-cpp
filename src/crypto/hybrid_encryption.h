#pragma once

#include <vector>
#include <cstdint>

namespace tor::hybrid_encryption {

// Constantes conforme tor-spec.txt 0.3.
static constexpr size_t KEY_LEN = 16;
static constexpr size_t PK_ENC_LEN = 128;
static constexpr size_t PK_PAD_LEN = 42;

static constexpr size_t PK_DATA_LEN = PK_ENC_LEN - PK_PAD_LEN;
static constexpr size_t PK_DATA_LEN_WITH_KEY = PK_DATA_LEN - KEY_LEN;

//
// Criptografa o conteúdo de "data" com a "public_key" dada (RSA)
// seguindo o esquema de criptografia híbrida do Tor.
//
std::vector<uint8_t>
encrypt(
  const std::vector<uint8_t>& data,
  const std::vector<uint8_t>& public_key
  );

}