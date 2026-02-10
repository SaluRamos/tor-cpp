#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace tor {

class consensus;

class onion_router
{
  public:
    enum class status_flag : uint16_t
    {
      none            = 0x0000,
      authority       = 0x0001,
      bad_exit        = 0x0002,
      exit            = 0x0004,
      fast            = 0x0008,
      guard           = 0x0010,
      hsdir           = 0x0020,
      named           = 0x0040,
      no_ed_consensus = 0x0080,
      stable          = 0x0100,
      running         = 0x0200,
      unnamed         = 0x0400,
      valid           = 0x0800,
      v2dir           = 0x1000,
    };

    // Usando uint16_t para representar o conjunto de flags
    using status_flags = uint16_t;

  public:
    onion_router(
      consensus& consensus,
      const std::string& name,
      const std::string& ip,
      uint16_t or_port,
      uint16_t dir_port,
      const std::vector<uint8_t>& identity_fingerprint
      );

    consensus& get_consensus();

    std::string get_name() const;
    void set_name(const std::string& value);

    // Representação de IP como string para simplificar sem mini::net::ip_address
    std::string get_ip_address() const;
    void set_ip_address(const std::string& value);

    uint16_t get_or_port() const;
    void set_or_port(uint16_t value);

    uint16_t get_dir_port() const;
    void set_dir_port(uint16_t value);

    const std::vector<uint8_t>& get_identity_fingerprint() const;
    void set_identity_fingerprint(const std::vector<uint8_t>& value);

    status_flags get_flags() const;
    void set_flags(status_flags flags);

    const std::vector<uint8_t>& get_onion_key();
    void set_onion_key(const std::vector<uint8_t>& value);

    const std::vector<uint8_t>& get_signing_key();
    void set_signing_key(const std::vector<uint8_t>& value);

    const std::vector<uint8_t>& get_ntor_onion_key();
    void set_ntor_onion_key(const std::vector<uint8_t>& value);

    const std::vector<uint8_t>& get_service_key();
    void set_service_key(const std::vector<uint8_t>& value);

  private:
    void fetch_descriptor();

    consensus& _consensus;

    std::string _name;
    std::string _ip;
    uint16_t _or_port;
    uint16_t _dir_port;

    std::vector<uint8_t> _identity_fingerprint; 
    status_flags _flags;

    std::vector<uint8_t> _onion_key;
    std::vector<uint8_t> _signing_key;
    std::vector<uint8_t> _ntor_onion_key;
    std::vector<uint8_t> _service_key; 

    bool _descriptor_fetched;
};

// Substituindo mini::collections::list por std::vector
using onion_router_list = std::vector<onion_router*>;

}