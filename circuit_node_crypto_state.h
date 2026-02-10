#pragma once
#include "cell.h"

#include <vector>
#include <array>
#include <cstdint>

// Assumindo que suas classes de crypto foram migradas ou são compatíveis com a CRT
// #include "crypto/aes.h"
// #include "crypto/sha1.h"

namespace tor {

class relay_cell;

class circuit_node_crypto_state
{
  public:
    // O material de chave (KDF) no Tor v2/v3 costuma ter 72 ou 92 bytes
    circuit_node_crypto_state(
      const std::vector<uint8_t>& key_material
    );

    ~circuit_node_crypto_state() = default;

    void encrypt_forward_cell(relay_cell& cell);
    bool decrypt_backward_cell(cell& cell);

  private:
    // Exemplo usando tipos genéricos de crypto que você deve ter no projeto
    // aes_ctr_128 _forward_cipher;
    // aes_ctr_128 _backward_cipher;
    // sha1 _forward_digest;
    // sha1 _backward_digest;

    // Se estiver usando OpenSSL ou Windows BCrypt, os handles ficariam aqui.
};

}