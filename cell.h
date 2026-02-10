#pragma once
#include "common.h"

#include <vector>
#include <cstdint>

namespace tor {

enum class cell_destroy_reason : uint8_t
{
    none                           =  0,
    protocol                       =  1,
    internal                       =  2,
    requested                      =  3,
    hibernating                    =  4,
    resource_limit                 =  5,
    connection_failed              =  6,
    onion_router_identity          =  7,
    onion_router_connection_closed =  8,
    finished                       =  9,
    timeout                        = 10,
    destroyed                      = 11,
    no_such_service                = 12,
};

enum class cell_command : uint8_t
{
    padding         = 0,
    create          = 1,
    created         = 2,
    relay           = 3,
    destroy         = 4,
    create_fast     = 5,
    created_fast    = 6,
    versions        = 7,
    netinfo         = 8,
    relay_early     = 9,
    create2         = 10,
    created2        = 11,
    padding_negotiate = 12,
    vpadding        = 128,
    certs           = 129,
    auth_challenge  = 130,
    authenticate    = 131,
    authorize       = 132
};

class cell
{
public:
    static constexpr size_t payload_size = 509;

    cell() = default;
    cell(const cell& other) = default;
    cell(cell&& other) noexcept;

    cell(
        circuit_id_type circuit_id,
        cell_command command,
        const std::vector<uint8_t>& payload = {}
    );

    ~cell() = default;

    cell& operator=(const cell& other) = default;
    void swap(cell& other) noexcept;

    circuit_id_type get_circuit_id() const;
    void set_circuit_id(circuit_id_type circuit_id);

    cell_command get_command() const;
    void set_command(cell_command command);

    const std::vector<uint8_t>& get_payload() const;
    void set_payload(const std::vector<uint8_t>& payload);

    std::vector<uint8_t> get_bytes(protocol_version_type protocol_version) const;

    bool is_recognized() const;
    bool is_valid() const;
    void mark_as_invalid();

private:
    bool is_variable_length_cell_command(cell_command command) const;

    circuit_id_type _circuit_id = 0;
    cell_command _command = cell_command::padding;
    std::vector<uint8_t> _payload;
    bool _is_valid = true;
};

}