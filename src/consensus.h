#pragma once

#include "onion_router.h"
#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <memory>

namespace tor {

class consensus
{
  public:
    struct search_criteria
    {
      std::vector<uint16_t> allowed_dir_ports;
      std::vector<uint16_t> allowed_or_ports;
      onion_router_list forbidden_onion_routers; // std::vector<onion_router*>
      onion_router::status_flags flags;
    };

    consensus(
      const std::string& cached_consensus_path = "",
      bool force_download = false
      );

    ~consensus();

    void create(
      const std::string& cached_consensus_path = "",
      bool force_download = false
      );

    void destroy();

    // Getters
    onion_router* get_onion_router_by_name(const std::string& name) const;
    
    onion_router* get_onion_router_by_identity_fingerprint(
      const std::vector<uint8_t>& identity_fingerprint
      );

    onion_router_list get_onion_routers_by_criteria(
      const search_criteria& criteria
      ) const;

    onion_router* get_random_onion_router_by_criteria(
      const search_criteria& criteria
      ) const;

    std::string get_onion_router_descriptor(
      const std::vector<uint8_t>& identity_fingerprint
      );

    // Configurações de diretório
    onion_router::status_flags get_allowed_dir_flags() const;
    void set_allowed_dir_flags(onion_router::status_flags allowed_dir_flags);

    const std::vector<uint16_t>& get_allowed_dir_ports() const;
    void set_allowed_dir_ports(const std::vector<uint16_t>& allowed_dir_ports);

    size_t get_max_try_count() const;
    void set_max_try_count(size_t max_try_count);

    std::string download_from_random_router(
      const std::string& path,
      bool only_authorities = false
      );

  private:
    friend struct consensus_parser;

    std::string download_from_random_router_impl(
      const std::string& path,
      bool only_authorities
      );

    void parse_consensus(
      const std::string& consensus_content,
      bool reject_invalid
      );

    onion_router::status_flags _allowed_dir_flags =
      static_cast<onion_router::status_flags>(onion_router::status_flag::fast) |
      static_cast<onion_router::status_flags>(onion_router::status_flag::valid) |
      static_cast<onion_router::status_flags>(onion_router::status_flag::running);

    std::vector<uint16_t> _allowed_dir_ports;
    size_t _max_try_count = 5;

    std::map<std::vector<uint8_t>, onion_router*> _onion_router_map;
    std::vector<onion_router*> _onion_router_list;
};

}