#include "onion_router.h"
#include "consensus.h"
// Assumindo que o parser também foi migrado para a CRT
#include "parsers/onion_router_descriptor_parser.h"

namespace tor {

onion_router::onion_router(
  consensus& consensus,
  const std::string& name,
  const std::string& ip,
  uint16_t or_port,
  uint16_t dir_port,
  const std::vector<uint8_t>& identity_fingerprint
  )
  : _consensus(consensus)
  , _name(name)
  , _ip(ip)
  , _or_port(or_port)
  , _dir_port(dir_port)
  , _identity_fingerprint(identity_fingerprint)
  , _flags(static_cast<status_flags>(status_flag::none))
  , _descriptor_fetched(false)
{
}

consensus& onion_router::get_consensus() {
  return _consensus;
}

std::string onion_router::get_name() const {
  return _name;
}

void onion_router::set_name(const std::string& value) {
  _name = value;
}

std::string onion_router::get_ip_address() const {
  return _ip;
}

void onion_router::set_ip_address(const std::string& value) {
  _ip = value;
}

uint16_t onion_router::get_or_port() const {
  return _or_port;
}

void onion_router::set_or_port(uint16_t value) {
  _or_port = value;
}

uint16_t onion_router::get_dir_port() const {
  return _dir_port;
}

void onion_router::set_dir_port(uint16_t value) {
  _dir_port = value;
}

const std::vector<uint8_t>& onion_router::get_identity_fingerprint() const {
  return _identity_fingerprint;
}

void onion_router::set_identity_fingerprint(const std::vector<uint8_t>& value) {
  _identity_fingerprint = value;
}

onion_router::status_flags onion_router::get_flags() const {
  return _flags;
}

void onion_router::set_flags(status_flags flags) {
  _flags = flags;
}

const std::vector<uint8_t>& onion_router::get_onion_key() {
  if (!_descriptor_fetched) {
    fetch_descriptor();
  }
  return _onion_key;
}

void onion_router::set_onion_key(const std::vector<uint8_t>& value) {
  _onion_key = value;
}

const std::vector<uint8_t>& onion_router::get_signing_key() {
  if (!_descriptor_fetched) {
    fetch_descriptor();
  }
  return _signing_key;
}

void onion_router::set_signing_key(const std::vector<uint8_t>& value) {
  _signing_key = value;
}

const std::vector<uint8_t>& onion_router::get_ntor_onion_key() {
  if (!_descriptor_fetched) {
    fetch_descriptor();
  }
  return _ntor_onion_key;
}

void onion_router::set_ntor_onion_key(const std::vector<uint8_t>& value) {
  _ntor_onion_key = value;
}

const std::vector<uint8_t>& onion_router::get_service_key() {
  return _service_key;
}

void onion_router::set_service_key(const std::vector<uint8_t>& value) {
  _service_key = value;
}

void onion_router::fetch_descriptor() {
  // O parser deve ser ajustado para aceitar std::vector e a nova estrutura da classe
  onion_router_descriptor_parser parser;
  parser.parse(this, _consensus.get_onion_router_descriptor(_identity_fingerprint));

  _descriptor_fetched = true;
}

}