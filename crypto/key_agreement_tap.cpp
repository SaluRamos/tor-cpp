#include "key_agreement_tap.h"
#include <algorithm>
#include <cstring>

namespace tor {

// Parâmetros do Grupo DH (RFC 2409 Section 6.2)
static const uint8_t DH_P[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
  0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
  0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
  0xef, 0x95, 0xad, 0x39, 0x8a, 0x28, 0x3e, 0x9a, 0x1f, 0x94, 0x6e, 0x37, 0xd6, 0x49, 0x10, 0x84,
  0x1b, 0x31, 0x09, 0x4b, 0x5f, 0xed, 0x92, 0x96, 0x8b, 0x15, 0xf8, 0x62, 0x70, 0x03, 0x02, 0xad,
  0x17, 0x11, 0x0b, 0x7b, 0x49, 0xda, 0x1c, 0xf2, 0x91, 0xba, 0x19, 0x8e, 0xeb, 0xca, 0x44, 0x1b,
  0xf1, 0x24, 0x68, 0x97, 0x47, 0x4e, 0x11, 0x2d, 0x49, 0x10, 0x18, 0xfd, 0xa2, 0x7d, 0xb4, 0x95,
  0x12, 0xc1, 0x96, 0x7b, 0x6a, 0xe1, 0x83, 0x12, 0x24, 0xcc, 0xe2, 0x29, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff
};

static const uint8_t DH_G[] = { 2 };

key_agreement_tap::key_agreement_tap(onion_router* router)
  : key_agreement(router)
{
  // Aqui você deve gerar as chaves usando sua lib de crypto vinculada à CRT
  // generate_dh_keys(_private_key, _public_key);
}

key_agreement_tap::key_agreement_tap(onion_router* router, std::vector<uint8_t>&& private_key)
  : key_agreement(router)
  , _private_key(std::move(private_key))
{
}

const std::vector<uint8_t>& key_agreement_tap::get_public_key() const
{
  return _public_key;
}

const std::vector<uint8_t>& key_agreement_tap::get_private_key() const
{
  return _private_key;
}

std::vector<uint8_t> key_agreement_tap::compute_shared_secret(
  const std::vector<uint8_t>& handshake_data)
{
  // TAP Client side: handshake_data contém a resposta do servidor
  // (g^y + digest)
  return std::vector<uint8_t>(); // Implementação de crypto omitida
}

std::vector<uint8_t> key_agreement_tap::compute_shared_secret(
  const std::vector<uint8_t>& other_public_key,
  const std::vector<uint8_t>& verification_data)
{
  // Verificação de segurança (tor-spec 5.2.1)
  // O valor recebido g^y deve ser: 1 < g^y < p-1
  // if (!is_dh_public_key_valid(other_public_key)) return {};

  // 1. Calcular g^xy
  // std::vector<uint8_t> shared_secret = dh_compute_secret(_private_key, other_public_key);

  // 2. Derivar chaves (KDF-TOR)
  // std::vector<uint8_t> derived = derive_keys(shared_secret);

  // 3. Verificar integridade (os primeiros 20 bytes costumam ser o digest de verificação)
  // if (std::memcmp(derived.data(), verification_data.data(), 20) != 0) return {};

  // Retornar o material de chave (pula o digest de verificação)
  return std::vector<uint8_t>(); 
}

}