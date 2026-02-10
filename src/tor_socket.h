#pragma once

#include <memory>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstdint>

// Classes que você já deve ter implementado (onion_router, cell, circuit)
#include "onion_router.h"
#include "cell.h"

namespace tor {

class circuit;

class tor_socket {
public:
    using protocol_version_type = uint32_t;
    using circuit_id_type = uint32_t;

    static constexpr protocol_version_type protocol_version_initial = 3;
    static constexpr protocol_version_type protocol_version_preferred = 4;

    tor_socket(onion_router* router = nullptr);
    ~tor_socket();

    void connect(onion_router* router);
    void close();

    circuit* create_circuit(int handshake_type = 0);
    void remove_circuit(circuit* circ);
    
    void send_cell(const cell& c);
    cell recv_cell();

    onion_router* get_onion_router() const { return _onion_router; }
    protocol_version_type get_protocol_version() const { return _protocol_version; }
    bool is_connected() const;
    bool is_ready() const;

private:

    enum class state {
        closed,
        connecting,
        handshake_in_progress,
        ready,
        closing
    };

    void set_state(state new_state);
    bool wait_for_state(state desired_state, int timeout_ms = 30000);

    // Handshake helpers
    void send_versions();
    void recv_versions();
    void send_net_info();
    void recv_net_info();
    void recv_certificates();
    void recv_cell_loop();

    std::unique_ptr<std::thread> _recv_thread;
    std::mutex _state_mutex;
    std::condition_variable _state_cv;
    state _current_state = state::closed;

    // Socket genérico (Substitua pelo seu wrapper de SSL/Socket favorito)
    // Aqui usamos um placeholder para o handle do socket
    intptr_t _socket_handle = -1; 

    onion_router* _onion_router = nullptr;
    uint32_t _protocol_version = protocol_version_initial;

    std::map<circuit_id_type, circuit*> _circuit_map;
    std::mutex _circuit_mutex;
};

}