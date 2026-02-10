#include "circuit.h"
#include "circuit_node.h"
#include "hidden_service.h"

#include <algorithm>
#include <chrono>

namespace tor {

void circuit::rendezvous_introduce(circuit* rendezvous_circ, const uint8_t* cookie)
{
    // Implementation placeholder:
    // 1. Construct the payload for INTRODUCE1 cell (containing the rendezvous cookie and public key info).
    // 2. Encrypt the payload if necessary (usually to the introduction point).
    // 3. Send the cell using send_relay_cell().
    
    // Example stub (prevent linker error):
    (void)rendezvous_circ;
    (void)cookie;
    
    // TODO: Implement the actual INTRODUCE1 cell creation logic here.
    // relay_cell cell(circuit_id, command::relay_introduce1, ...);
    // send_relay_cell(cell);
    
    // Update state if needed
    set_state(state::rendezvous_introduced);
}

circuit::circuit(tor_socket& socket)
  : _tor_socket(socket)
  , _circuit_id(get_next_circuit_id())
{
    // Define o MSB para indicar que somos o iniciador (v3+ protocol)
    _circuit_id |= 0x80000000;
}

circuit::~circuit()
{
    send_destroy_cell();
    destroy();
}

void circuit::destroy()
{
    std::lock_guard<std::mutex> lock(_circuit_mutex);
    _stream_map.clear();
    _node_list.clear();
    set_state(state::destroyed);
}

tor_stream* circuit::get_stream_by_id(tor_stream_id_type stream_id)
{
    std::lock_guard<std::mutex> lock(_circuit_mutex);
    auto it = _stream_map.find(stream_id);
    return (it != _stream_map.end()) ? it->second.get() : nullptr;
}

void circuit::set_state(state new_state)
{
    {
        std::lock_guard<std::mutex> lock(_state_mutex);
        _state = new_state;
    }
    _state_cv.notify_all();
}

bool circuit::wait_for_state(state desired_state, uint32_t timeout_ms)
{
    std::unique_lock<std::mutex> lock(_state_mutex);
    return _state_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
        [this, desired_state] { return _state.load() == desired_state; });
}

void circuit::handle_cell(cell& c)
{
    // Descriptografar a célula através das camadas dos nós (camadas da cebola)
    // relay_cell r_cell = decrypt_layers(c);
    
    switch (c.get_command())
    {
        case cell_command::created:
        case cell_command::created2:
            // handle_created_cell(c);
            break;
        case cell_command::relay:
        case cell_command::relay_early:
            // handle_relay_cell(r_cell);
            break;
        case cell_command::destroy:
            destroy();
            break;
        default:
            break;
    }
}

void circuit::handle_relay_end_cell(relay_cell& cell)
{
    std::lock_guard<std::mutex> lock(_circuit_mutex);
    tor_stream_id_type s_id = cell.get_stream_id();
    
    auto it = _stream_map.find(s_id);
    if (it != _stream_map.end())
    {
        it->second->set_state(tor_stream::state::destroyed);
        _stream_map.erase(it);
    }
}

circuit_id_type circuit::get_next_circuit_id()
{
    static std::atomic<circuit_id_type> next_id{1};
    return next_id.fetch_add(1);
}

tor_stream_id_type circuit::get_next_stream_id()
{
    static std::atomic<tor_stream_id_type> next_id{1};
    return next_id.fetch_add(1);
}

// Getters básicos migrados para CRT
tor_socket& circuit::get_tor_socket() { return _tor_socket; }
circuit_id_type circuit::get_circuit_id() const { return _circuit_id; }
const circuit_node_list& circuit::get_circuit_node_list() const { return _node_list; }
size_t circuit::get_circuit_node_list_size() const { return _node_list.size(); }

circuit::state circuit::get_state() const { return _state.load(); }

}