#pragma once

#include <vector>
#include <cstdint>

// O onion_router.h já deve ter sido migrado para usar std::string/std::vector
#include "../onion_router.h"

namespace tor {

class key_agreement
{
  public:
    key_agreement(
      onion_router* router
      )
      : _onion_router(router)
    {
    }

    virtual ~key_agreement() = default;

    // Retorna a chave pública local gerada para o handshake
    virtual const std::vector<uint8_t>&
    get_public_key() const = 0;

    // Retorna a chave privada local gerada para o handshake
    virtual const std::vector<uint8_t>&
    get_private_key() const = 0;

    // Computa o segredo compartilhado a partir dos dados brutos do handshake recebido
    virtual std::vector<uint8_t>
    compute_shared_secret(
      const std::vector<uint8_t>& handshake_data
      ) = 0;

    // Computa o segredo e verifica a integridade usando dados de verificação (KH)
    virtual std::vector<uint8_t>
    compute_shared_secret(
      const std::vector<uint8_t>& other_public_key,
      const std::vector<uint8_t>& verification_data // Derivative key data (KH)
      ) = 0;

  protected:
    onion_router* _onion_router;
};

}