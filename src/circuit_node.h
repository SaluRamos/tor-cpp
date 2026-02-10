#pragma once
#include "circuit_node_crypto_state.h"
#include "crypto/key_agreement.h"
#include "relay_cell.h"

#include <memory>
#include <mutex>
#include <vector>
#include <cstdint>

namespace tor {

class circuit;

class circuit_node
{
  public:
    circuit_node(
      circuit* circuit,
      onion_router* router,
      circuit_node_type node_type = circuit_node_type::normal
      );

    ~circuit_node();

    circuit* get_circuit();
    circuit_node_type get_circuit_node_type() const;
    onion_router* get_onion_router();
    
    key_agreement& get_key_agreement();

    std::vector<uint8_t> create_onion_skin();
    std::vector<uint8_t> create_onion_skin_ntor();

    void compute_shared_secret(const std::vector<uint8_t>& cell_payload);

    bool has_valid_crypto_state() const;

    void encrypt_forward_cell(relay_cell& cell);
    bool decrypt_backward_cell(cell& cell);

    // Controle de fluxo (Flow Control)
    void decrement_package_window();
    void increment_package_window();
    void decrement_deliver_window();
    bool consider_sending_sendme();

  private:
    static constexpr size_t window_start = 1000;
    static constexpr size_t window_increment = 100;

    circuit* _circuit;
    circuit_node_type _type;
    onion_router* _onion_router;

    std::unique_ptr<key_agreement> _handshake;
    std::unique_ptr<circuit_node_crypto_state> _crypto_state;

    mutable std::mutex _window_mutex;
    int32_t _package_window = window_start;
    int32_t _deliver_window = window_start;
};

}