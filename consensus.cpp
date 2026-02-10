#include "consensus.h"
#include <algorithm>
#include <random>
#include <fstream>
#include <iostream>

namespace tor {

consensus::consensus(
  const std::string& cached_consensus_path,
  bool force_download
  )
{
  create(cached_consensus_path, force_download);
}

consensus::~consensus()
{
  destroy();
}

void consensus::destroy()
{
  for (auto router : _onion_router_list)
  {
    delete router;
  }
  _onion_router_list.clear();
  _onion_router_map.clear();
}

onion_router* consensus::get_random_onion_router_by_criteria(
  const search_criteria& criteria
  ) const
{
  auto routers = get_onion_routers_by_criteria(criteria);
  
  if (routers.empty()) {
    return nullptr;
  }

  // Uso de <random> da CRT padrão
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dis(0, routers.size() - 1);

  return routers[dis(gen)];
}

std::string consensus::download_from_random_router(
  const std::string& path,
  bool only_authorities
  )
{
  size_t try_count = 0;
  std::string result;

  do
  {
    result = download_from_random_router_impl(path, only_authorities);
  } while (++try_count < _max_try_count && result.empty());

  return result;
}

std::string consensus::download_from_random_router_impl(
  const std::string& path,
  bool only_authorities
  )
{
  std::string ip;
  uint16_t port;

  if (only_authorities || _onion_router_map.empty())
  {
    // Lógica para autoridades hardcoded (Exemplo simplificado)
    ip = "128.31.0.39"; 
    port = 9131;
  }
  else
  {
    search_criteria criteria;
    criteria.allowed_dir_ports = _allowed_dir_ports;
    criteria.flags = _allowed_dir_flags;

    auto router = get_random_onion_router_by_criteria(criteria);
    if (!router) return "";

    ip = router->get_ip_address();
    port = router->get_dir_port();
  }

  // Aqui você deve integrar sua chamada HTTP de preferência (ex: WinHTTP ou cURL)
  // std::string response = http_get(ip, port, path);
  // return response;
  
  return ""; 
}

void consensus::parse_consensus(
  const std::string& consensus_content,
  bool reject_invalid
  )
{
    // A implementação do parser deve ser adaptada para preencher _onion_router_list
    // e _onion_router_map usando std::vector::push_back e std::map::insert
}

}