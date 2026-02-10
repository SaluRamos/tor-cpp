#include "hybrid_encryption.h"
#include <cstring>
#include <algorithm>

// Nota: Para /nodefaultlib, você precisará de wrappers para RSA e AES
// que usem BCrypt ou OpenSSL.
// #include "crypto/rsa_wrapper.h"
// #include "crypto/aes_wrapper.h"
// #include "crypto/random_wrapper.h"

namespace tor::hybrid_encryption {

std::vector<uint8_t>
encrypt(
  const std::vector<uint8_t>& data,
  const std::vector<uint8_t>& public_key
  )
{
  // Se os dados cabem em um único bloco RSA (PKCS1-OAEP)
  if (data.size() < PK_DATA_LEN)
  {
    // return rsa_encrypt_simple(data, public_key);
    return std::vector<uint8_t>(); 
  }

  // 1. Gerar chave AES de 128 bits (16 bytes)
  std::vector<uint8_t> random_key(KEY_LEN);
  // crypto::get_random_bytes(random_key.data(), KEY_LEN);

  // 2. Preparar C1: RSA( K | M1 )
  // M1 são os primeiros (PK_DATA_LEN - KEY_LEN) bytes de data
  std::vector<uint8_t> k_and_m1;
  k_and_m1.reserve(PK_DATA_LEN);
  k_and_m1.insert(k_and_m1.end(), random_key.begin(), random_key.end());
  k_and_m1.insert(k_and_m1.end(), data.begin(), data.begin() + PK_DATA_LEN_WITH_KEY);

  // auto c1 = rsa_encrypt_oaep(k_and_m1, public_key);
  std::vector<uint8_t> c1; // Resultado do RSA

  // 3. Preparar C2: AES_CTR(M2) com a chave K gerada
  // M2 é o restante dos dados
  std::vector<uint8_t> m2(data.begin() + PK_DATA_LEN_WITH_KEY, data.end());
  
  // auto c2 = aes_ctr_encrypt(m2, random_key);
  std::vector<uint8_t> c2; // Resultado do AES

  // 4. Concatenar C1 | C2
  std::vector<uint8_t> result;
  result.reserve(c1.size() + c2.size());
  result.insert(result.end(), c1.begin(), c1.end());
  result.insert(result.end(), c2.begin(), c2.end());

  return result;
}

}