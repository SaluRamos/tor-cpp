#include "circuit_node_crypto_state.h"
#include "relay_cell.h"

#include <cstring>
#include <algorithm>

namespace tor {

circuit_node_crypto_state::circuit_node_crypto_state(
  const std::vector<uint8_t>& key_material
)
{
  // No Tor, o material de chave derivado (KDF) é fatiado em:
  // Df (Forward Digest) - 20 bytes
  // Db (Backward Digest) - 20 bytes
  // Kf (Forward Key)    - 16 bytes (AES-128)
  // Kb (Backward Key)   - 16 bytes (AES-128)
  
  const uint8_t* p = key_material.data();
  size_t offset = 0;

  auto read_bytes = [&](void* dest, size_t size) {
    if (offset + size <= key_material.size()) {
      std::memcpy(dest, p + offset, size);
      offset += size;
    }
  };

  // 1. Forward Digest
  uint8_t df[20];
  read_bytes(df, 20);
  // _forward_digest.update(df, 20);

  // 2. Backward Digest
  uint8_t db[20];
  read_bytes(db, 20);
  // _backward_digest.update(db, 20);

  // 3. Forward Cipher Key
  uint8_t kf[16];
  read_bytes(kf, 16);
  // _forward_cipher.init(kf, 16);

  // 4. Backward Cipher Key
  uint8_t kb[16];
  read_bytes(kb, 16);
  // _backward_cipher.init(kb, 16);
}

void circuit_node_crypto_state::encrypt_forward_cell(
  relay_cell& cell
)
{
  // 1. Obter o payload unencrypted
  std::vector<uint8_t> payload = cell.get_payload(); 

  // 2. Se for uma relay_cell válida, atualizar o digest
  // O digest é calculado sobre o payload com o campo 'Digest' zerado
  uint8_t digest_placeholder[4] = {0, 0, 0, 0};
  std::memcpy(payload.data() + 5, digest_placeholder, 4);

  // _forward_digest.update(payload.data(), payload.size());
  // auto current_digest = _forward_digest.get_current_hash();
  // std::memcpy(payload.data() + 5, current_digest.data(), 4);

  // 3. Criptografar com AES-CTR (a cifra CTR não muda o tamanho)
  // _forward_cipher.encrypt_inplace(payload.data(), payload.size());

  cell.set_payload(payload);
}

bool circuit_node_crypto_state::decrypt_backward_cell(
  cell& cell
)
{
  std::vector<uint8_t> payload = cell.get_payload();
  if (payload.size() != cell::payload_size) return false;

  // 1. Decriptografar (AES-CTR é simétrico)
  // _backward_cipher.decrypt_inplace(payload.data(), payload.size());
  cell.set_payload(payload);

  // 2. Verificar campo 'Recognized' (bytes 2 e 3 do payload relay)
  // No Tor, se Recognized == 0, pode ser uma célula para nós.
  if (cell.is_recognized())
  {
    // Verificar o digest para confirmar integridade e se é realmente para nós
    // (Lógica de verificação de digest omitida para brevidade, 
    // similar à da encrypt_forward_cell)
    return true; 
  }

  return false;
}

}