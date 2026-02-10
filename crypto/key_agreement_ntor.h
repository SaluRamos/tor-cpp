#pragma once
#include "key_agreement.h"
#include <vector>
#include <cstdint>
#include <memory>

namespace tor {

class key_agreement_ntor
  : public key_agreement
{
  public:
    key_agreement_ntor(
      onion_router* router
      );

    key_agreement_ntor(
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
      const std::vector<uint8_t>& auth_data
      ) override;

  private:
    std::vector<uint8_t> _public_key;
    std::vector<uint8_t> _private_key;
};

}