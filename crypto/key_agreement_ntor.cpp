#include "key_agreement_ntor.h"
#include <cstring>
#include <algorithm>

namespace tor {

// Constantes do protocolo nTor (conforme tor-spec.txt)
static const uint8_t PROTOID[]  = "ntor-curve25519-sha256-1";
static const uint8_t T_MAC[]    = "ntor-curve25519-sha256-1:mac";
static const uint8_t T_VERIFY[] = "ntor-curve25519-sha256-1:verify";
static const uint8_t T_KEY[]    = "ntor-curve25519-sha256-1:key_extract";
static const uint8_t M_EXPAND[] = "ntor-curve25519-sha256-1:key_expand";
static const uint8_t SERVER_STR[] = "Server";

key_agreement_ntor::key_agreement_ntor(onion_router* router)
  : key_agreement(router)
{
  // _private_key = crypto::curve25519::generate_private();
  // _public_key  = crypto::curve25519::get_public(_private_key);
}

key_agreement_ntor::key_agreement_ntor(onion_router* router, std::vector<uint8_t>&& private_key)
  : key_agreement(router)
  , _private_key(std::move(private_key))
{
  // _public_key = crypto::curve25519::get_public(_private_key);
}

const std::vector<uint8_t>& key_agreement_ntor::get_public_key() const
{
  return _public_key;
}

const std::vector<uint8_t>& key_agreement_ntor::get_private_key() const
{
  return _private_key;
}

std::vector<uint8_t> key_agreement_ntor::compute_shared_secret(
  const std::vector<uint8_t>& handshake_data)
{
  // No nTor, a resposta do servidor contém a chave pública Y e o AUTH tag.
  if (handshake_data.size() < 32 + 32) return {};

  std::vector<uint8_t> Y(handshake_data.begin(), handshake_data.begin() + 32);
  std::vector<uint8_t> AUTH(handshake_data.begin() + 32, handshake_data.end());

  return compute_shared_secret(Y, AUTH);
}

std::vector<uint8_t> key_agreement_ntor::compute_shared_secret(
  const std::vector<uint8_t>& other_public_key, // Y
  const std::vector<uint8_t>& auth_tag          // AUTH
)
{
  // 1. Calcular segredos compartilhados (EXP(Y,x) e EXP(B,x))
  // auto shared1 = crypto::curve25519::scalarmult(_private_key, other_public_key);
  // auto shared2 = crypto::curve25519::scalarmult(_private_key, _onion_router->get_ntor_onion_key());

  // 2. Construir secret_input
  // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
  std::vector<uint8_t> secret_input;
  auto append = [&](const std::vector<uint8_t>& data) {
    secret_input.insert(secret_input.end(), data.begin(), data.end());
  };

  // Exemplo de construção (os métodos abaixo devem retornar std::vector)
  // append(shared1);
  // append(shared2);
  append(_onion_router->get_identity_fingerprint());
  append(_onion_router->get_ntor_onion_key());
  append(_public_key);
  append(other_public_key);
  secret_input.insert(secret_input.end(), PROTOID, PROTOID + sizeof(PROTOID) - 1);

  // 3. Verificação HMAC
  // auto verify = crypto::hmac_sha256::compute(T_VERIFY, secret_input);
  
  // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
  // if (crypto::hmac_sha256::compute(T_MAC, auth_input) != auth_tag) return {};

  // 4. Derivação de Chave (HKDF)
  // return crypto::hkdf_sha256::expand(T_KEY, secret_input, M_EXPAND, 72);
  
  return std::vector<uint8_t>(); 
}

}