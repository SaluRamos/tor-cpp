#include "circuit_node.h"
#include "circuit.h"
#include "crypto/hybrid_encryption.h"
#include "crypto/key_agreement_tap.h"
#include "crypto/key_agreement_ntor.h"

#include <algorithm>
#include <cstring>

namespace tor {

circuit_node::circuit_node(
  circuit* circuit,
  onion_router* router,
  circuit_node_type node_type
  )
  : _circuit(circuit)
  , _type(node_type)
  , _onion_router(router)
{
  if (_type == circuit_node_type::introduction_point)
  {
    _handshake = std::make_unique<key_agreement_tap>(_onion_router);
  }
}

circuit_node::~circuit_node() = default;

circuit* circuit_node::get_circuit() { return _circuit; }

circuit_node_type circuit_node::get_circuit_node_type() const { return _type; }

onion_router* circuit_node::get_onion_router() { return _onion_router; }

key_agreement& circuit_node::get_key_agreement() { return *_handshake; }

std::vector<uint8_t> circuit_node::create_onion_skin()
{
  _handshake = std::make_unique<key_agreement_tap>(_onion_router);
  // Assume que hybrid_encryption::encrypt agora retorna std::vector<uint8_t>
  return hybrid_encryption::encrypt(_handshake->get_public_key(), _onion_router->get_onion_key());
}

std::vector<uint8_t> circuit_node::create_onion_skin_ntor()
{
  _handshake = std::make_unique<key_agreement_ntor>(_onion_router);
  return _handshake->get_public_key();
}

void circuit_node::compute_shared_secret(const std::vector<uint8_t>& cell_payload)
{
  _crypto_state = std::make_unique<circuit_node_crypto_state>(
    _handshake->compute_shared_secret(cell_payload)
  );
}

bool circuit_node::has_valid_crypto_state() const
{
  return _crypto_state != nullptr;
}

void circuit_node::encrypt_forward_cell(relay_cell& cell)
{
  if (_crypto_state) {
    _crypto_state->encrypt_forward_cell(cell);
  }
}

bool circuit_node::decrypt_backward_cell(cell& cell)
{
  return _crypto_state ? _crypto_state->decrypt_backward_cell(cell) : false;
}

// Implementação de controle de fluxo com mutex CRT
void circuit_node::decrement_package_window()
{
  std::lock_guard<std::mutex> lock(_window_mutex);
  _package_window--;
}

void circuit_node::increment_package_window()
{
  std::lock_guard<std::mutex> lock(_window_mutex);
  _package_window += window_increment;
}

void circuit_node::decrement_deliver_window()
{
  std::lock_guard<std::mutex> lock(_window_mutex);
  _deliver_window--;
}

bool circuit_node::consider_sending_sendme()
{
  std::lock_guard<std::mutex> lock(_window_mutex);
  if (_deliver_window <= (window_start - window_increment))
  {
    _deliver_window += window_increment;
    return true;
  }
  return false;
}

}