#include "hidden_service.h"

#include <algorithm>
#include <iostream>
#include <chrono>
#include <cstring>

// Inclua seus headers de crypto que agora devem aceitar std::vector/std::array
// #include "crypto/base32.h"
// #include "crypto/random.h"

namespace tor {

hidden_service::hidden_service(
  circuit* rendezvous_circuit,
  const std::string& onion
  )
  : _rendezvous_circuit(rendezvous_circuit)
  , _socket(rendezvous_circuit->get_tor_socket())
  , _consensus(rendezvous_circuit->get_tor_socket().get_onion_router()->get_consensus())
  , _onion(onion)
{
    // Exemplo de conversão: crypto::base32::decode agora retorna std::vector
    // _permanent_id = crypto::base32::decode(_onion);
}

bool
hidden_service::connect()
{
  find_responsible_directories();

  if (!_responsible_directory_list.empty())
  {
    // Gerar cookie de rendezvous (Substituindo crypto::random_device)
    // crypto::get_random_bytes(_rendezvous_cookie.data(), _rendezvous_cookie.size());

    if (fetch_hidden_service_descriptor() != static_cast<size_t>(-1))
    {
      introduce();
    }
  }

  return _rendezvous_circuit->get_state() == circuit::state::rendezvous_established;
}

void
hidden_service::introduce()
{
  for (auto* introduction_point : _introduction_point_list)
  {
    std::cout << "Tentando ponto de introdução: " << introduction_point->get_name() << std::endl;

    // ptr<circuit> substituído por std::unique_ptr ou ponteiro bruto dependendo da sua gestão de memória
    circuit* introduce_circuit = _socket.create_circuit();

    if (!introduce_circuit)
    {
      continue;
    }

    introduce_circuit->extend(introduction_point);

    if (!introduce_circuit->is_ready())
    {
      // Em uma CRT real, você usaria delete se create_circuit der ownership
      // delete introduce_circuit; 
      continue;
    }

    // Enviar a célula de introdução
    introduce_circuit->rendezvous_introduce(_rendezvous_circuit, _rendezvous_cookie.data());

    if (introduce_circuit->get_state() == circuit::state::rendezvous_introduced)
    {
        std::cout << "Introdução aceita!" << std::endl;
        break; 
    }
  }
}

// Stub para lógica de diretórios responsáveis
void
hidden_service::find_responsible_directories()
{
    // Limpa a lista usando std::vector
    _responsible_directory_list.clear();
    
    // Lógica para preencher com _consensus.get_onion_routers()...
}

}