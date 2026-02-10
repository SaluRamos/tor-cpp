#pragma once
#include "key_agreement.h"
#include <vector>
#include <cstdint>

namespace tor {

class key_agreement_tap
  : public key_agreement
{
  public:
    // TAP utiliza DH de 1024 bits
    static constexpr size_t dh_key_size = 128; 

    key_agreement_tap(
      onion_router* router
      );

    // Construtor com chave privada existente (movimentação)
    key_agreement_tap(
      onion_router* router,
      std::vector<uint8_t>&& private_key
      );

    const std::vector<uint8_t>&
    get_public_key() const override;

    const std::vector<uint8_t>&
    get_private_key() const override;

    std::vector<uint8_t>
    compute_shared_secret(
      const std::vector<uint8_t>& handshake_data
      ) override;

    std::vector<uint8_t>
    compute_shared_secret(
      const std::vector<uint8_t>& other_public_key,
      const std::vector<uint8_t>& verification_data
      ) override;

  private:
    // Containers CRT
    std::vector<uint8_t> _public_key;
    std::vector<uint8_t> _private_key;
};

}