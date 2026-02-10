#include "relay_cell.h"
#include "circuit_node.h"
#include "circuit.h"
#include <cstring> // Para memcpy

// Helper simples para ler Big Endian de um buffer
template <typename T>
T read_be(const uint8_t*& ptr) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        value = (value << 8) | *ptr++;
    }
    return value;
}

namespace tor {

relay_cell::relay_cell(
    circuit_node* node,
    const cell& c
) : cell(c)
  , _circuit_node(node)
{
    const std::vector<uint8_t>& raw_payload = c.get_payload();
    if (raw_payload.size() < header_size) return;

    const uint8_t* ptr = raw_payload.data();

    // 6.1. Relay cell payload format
    _relay_command  = static_cast<cell_command>(read_be<uint8_t>(ptr));
    uint16_t recognized = read_be<uint16_t>(ptr); // 'Recognized'
    _stream_id      = read_be<uint16_t>(ptr);
    
    // Copia o digest (4 bytes)
    std::memcpy(_digest, ptr, 4);
    ptr += 4;

    uint16_t payload_length = read_be<uint16_t>(ptr);

    // Evita overflow/leitura fora do limite
    if (payload_length > payload_data_size) {
        payload_length = static_cast<uint16_t>(payload_data_size);
    }

    _relay_payload.assign(ptr, ptr + payload_length);
}

relay_cell::relay_cell(
    circuit_id_type circuit_id,
    cell_command command,
    circuit_node* node,
    cell_command relay_command,
    tor_stream_id_type stream_id,
    const std::vector<uint8_t>& relay_payload
) : cell(circuit_id, command)
  , _circuit_node(node)
  , _relay_command(relay_command)
  , _stream_id(stream_id)
  , _relay_payload(relay_payload)
{
}

cell_command relay_cell::get_relay_command() const {
    return _relay_command;
}

tor_stream_id_type relay_cell::get_stream_id() const {
    return _stream_id;
}

tor_stream* relay_cell::get_stream() {
    if (_circuit_node && _circuit_node->get_circuit()) {
        return _circuit_node->get_circuit()->get_stream_by_id(_stream_id);
    }
    return nullptr;
}

void relay_cell::set_digest(const uint8_t* digest_ptr) {
    if (digest_ptr) {
        std::memcpy(_digest, digest_ptr, 4);
    }
}

const std::vector<uint8_t>& relay_cell::get_relay_payload() const {
    return _relay_payload;
}

void relay_cell::set_relay_payload(const std::vector<uint8_t>& payload) {
    _relay_payload = payload;
}

circuit_node* relay_cell::get_circuit_node() {
    return _circuit_node;
}

bool relay_cell::is_relay_cell_valid() const {
    return _circuit_node != nullptr;
}

}