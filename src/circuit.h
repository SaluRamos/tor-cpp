#pragma once
#include "tor_socket.h"
#include "tor_stream.h"
#include "relay_cell.h"

#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace tor {

class circuit_node;

// Usando containers da CRT padrão
using circuit_node_list = std::vector<std::unique_ptr<circuit_node>>;

class circuit
{
  public:
    enum class state
    {
      none,
      creating,
      ready,
      extending,
      rendezvous_introduced,
      rendezvous_established,
      destroyed,
    };

    circuit(tor_socket& socket);
    ~circuit();

    tor_socket& get_tor_socket();
    circuit_id_type get_circuit_id() const;

    const circuit_node_list& get_circuit_node_list() const;
    size_t get_circuit_node_list_size() const;
    circuit_node* get_final_circuit_node();

    // Gerenciamento de Streams
    tor_stream* create_stream(const std::string& host, uint16_t port);
    tor_stream* create_onion_stream(const std::string& onion, uint16_t port);
    tor_stream* create_dir_stream();
    tor_stream* get_stream_by_id(tor_stream_id_type stream_id);

    // Ciclo de vida do Circuito
    void create(onion_router* first_router, handshake_type handshake = preferred_handshake_type);
    void extend(onion_router* next_router, handshake_type handshake = preferred_handshake_type);
    void destroy();

    // Comunicação
    void send_relay_cell(relay_cell& cell);
    void send_relay_data(tor_stream* stream, const std::vector<uint8_t>& buffer);
    void handle_cell(cell& c);

    state get_state() const;
    void set_state(state new_state);
    bool wait_for_state(state desired_state, uint32_t timeout_ms = 30000);

  private:
    friend class tor_socket;

    static circuit_id_type get_next_circuit_id();
    static tor_stream_id_type get_next_stream_id();

    // Handlers internos
    void handle_relay_cell(relay_cell& cell);
    void handle_relay_data_cell(relay_cell& cell);
    void handle_relay_end_cell(relay_cell& cell);
    void send_destroy_cell();

    tor_socket& _tor_socket;
    circuit_id_type _circuit_id;
    
    circuit_node_list _node_list;
    
    // Mapeamento de streams usando std::map da CRT
    std::map<tor_stream_id_type, std::unique_ptr<tor_stream>> _stream_map;
    mutable std::mutex _circuit_mutex;

    std::atomic<state> _state{state::none};
    std::mutex _state_mutex;
    std::condition_variable _state_cv;
};

}