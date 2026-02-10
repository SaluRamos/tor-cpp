#pragma once
#include "cell.h"
#include <vector>
#include <cstdint>

namespace tor {

class circuit_node;
class tor_stream;

// 6.3. - Motivos de fechamento de stream
enum class relay_end_reason : uint8_t
{
    misc                   =  1,
    resolve_failed         =  2,
    connection_refused     =  3,
    exit_policy            =  4,
    destroy                =  5,
    done                   =  6,
    timeout                =  7,
    no_route               =  8,
    hibernating            =  9,
    internal               = 10,
    resource_limit         = 11,
    connection_reset       = 12,
    tor_protocol_violation = 13,
    not_directory          = 14,
};

class relay_cell : public cell
{
public:
    // O cabeçalho de uma célula relay tem 11 bytes (1+2+2+4+2)
    static constexpr size_t header_size = 11;
    static constexpr size_t payload_data_size = cell::payload_size - header_size;

    relay_cell() = default;

    relay_cell(
        circuit_node* node,
        const cell& c
    );

    relay_cell(
        circuit_id_type circuit_id,
        cell_command command,
        circuit_node* node,
        cell_command relay_command,
        tor_stream_id_type stream_id,
        const std::vector<uint8_t>& relay_payload
    );

    cell_command get_relay_command() const;
    tor_stream_id_type get_stream_id() const;
    tor_stream* get_stream();

    void set_digest(const uint8_t* digest_ptr);
    const std::vector<uint8_t>& get_relay_payload() const;
    void set_relay_payload(const std::vector<uint8_t>& payload);

    circuit_node* get_circuit_node();
    bool is_relay_cell_valid() const;

private:
    circuit_node* _circuit_node = nullptr;
    cell_command _relay_command = (cell_command)0;
    tor_stream_id_type _stream_id = 0;
    uint8_t _digest[4] = {0};
    std::vector<uint8_t> _relay_payload;
};

}