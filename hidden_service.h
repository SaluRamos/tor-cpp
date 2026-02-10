#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>

// Assumindo que estas classes também foram migradas para a CRT
#include "circuit.h"
#include "consensus.h"

namespace tor {

using replica_type = uint8_t;

class hidden_service
{
  public:
    hidden_service(
      circuit* rendezvous_circuit,
      const std::string& onion
      );

    bool
    connect();

  private:
    std::vector<uint8_t>
    get_secret_id(
      replica_type replica
      );

    std::vector<uint8_t>
    get_descriptor_id(
      replica_type replica
      );

    void
    find_responsible_directories();

    // Retorna o índice
    size_t
    fetch_hidden_service_descriptor(
      size_t responsible_directory_index = 0
      );

    void
    introduce();

    circuit* _rendezvous_circuit;
    tor_socket& _socket;
    consensus& _consensus;

    std::string _onion;
    std::vector<uint8_t> _permanent_id; 

    // onion_router_list agora é std::vector<onion_router*>
    onion_router_list _responsible_directory_list;
    onion_router_list _introduction_point_list;

    // Substituindo stack_byte_buffer por std::array
    std::array<uint8_t, 20> _rendezvous_cookie;
};

}