#include "cell.h"
#include <algorithm>
#include <cstring>

namespace tor {

cell::cell(cell&& other) noexcept
{
    swap(other);
}

cell::cell(
    circuit_id_type circuit_id,
    cell_command command,
    const std::vector<uint8_t>& payload
) : _circuit_id(circuit_id)
  , _command(command)
  , _payload(payload)
{
}

void cell::swap(cell& other) noexcept
{
    std::swap(_circuit_id, other._circuit_id);
    std::swap(_command, other._command);
    std::swap(_payload, other._payload);
    std::swap(_is_valid, other._is_valid);
}

circuit_id_type cell::get_circuit_id() const { return _circuit_id; }
void cell::set_circuit_id(circuit_id_type circuit_id) { _circuit_id = circuit_id; }

cell_command cell::get_command() const { return _command; }
void cell::set_command(cell_command command) { _command = command; }

const std::vector<uint8_t>& cell::get_payload() const { return _payload; }
void cell::set_payload(const std::vector<uint8_t>& payload) { _payload = payload; }

std::vector<uint8_t> cell::get_bytes(protocol_version_type protocol_version) const
{
    std::vector<uint8_t> bytes;
    // Reserva espaço para evitar realocações: Header (3 ou 5 bytes) + Payload
    bytes.reserve(5 + _payload.size());

    // 1.1. CircID (v3 = 2 bytes, v4+ = 4 bytes)
    if (protocol_version < 4)
    {
        uint16_t id16 = static_cast<uint16_t>(_circuit_id);
        bytes.push_back(static_cast<uint8_t>(id16 >> 8));
        bytes.push_back(static_cast<uint8_t>(id16 & 0xFF));
    }
    else
    {
        bytes.push_back(static_cast<uint8_t>(_circuit_id >> 24));
        bytes.push_back(static_cast<uint8_t>(_circuit_id >> 16));
        bytes.push_back(static_cast<uint8_t>(_circuit_id >> 8));
        bytes.push_back(static_cast<uint8_t>(_circuit_id & 0xFF));
    }

    // 2. Command
    bytes.push_back(static_cast<uint8_t>(_command));

    // 3. Length (apenas para comandos de tamanho variável)
    if (is_variable_length_cell_command(_command))
    {
        uint16_t len = static_cast<uint16_t>(_payload.size());
        bytes.push_back(static_cast<uint8_t>(len >> 8));
        bytes.push_back(static_cast<uint8_t>(len & 0xFF));
    }

    // 4. Payload
    bytes.insert(bytes.end(), _payload.begin(), _payload.end());

    return bytes;
}

bool cell::is_recognized() const
{
    // Um relay cell reconhecido tem os bytes 2 e 3 do payload zerados
    if (_payload.size() < 4) return false;
    return (_payload[1] == 0 && _payload[2] == 0);
}

bool cell::is_valid() const { return _is_valid; }
void cell::mark_as_invalid() { _is_valid = false; }

bool cell::is_variable_length_cell_command(cell_command command) const
{
    uint8_t cmd = static_cast<uint8_t>(command);
    // De acordo com tor-spec, comandos >= 128 são variáveis, exceto casos específicos
    return (cmd == 7 || cmd >= 128); 
}

}