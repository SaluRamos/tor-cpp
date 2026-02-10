#include "tor_stream.h"
#include "circuit.h"

#include <algorithm>
#include <thread>
#include <chrono>
#include <cstring>

namespace tor {

tor_stream::tor_stream(
  tor_stream_id_type stream_id,
  circuit* circuit
  )
  : _stream_id(stream_id)
  , _circuit(circuit)
{
}

tor_stream::~tor_stream()
{
  close();
}

void tor_stream::close()
{
  set_state(state::destroyed);
  _buffer_cv.notify_all();
}

tor_stream_id_type tor_stream::get_stream_id() const
{
  return _stream_id;
}

void tor_stream::set_state(state new_state)
{
  {
    std::lock_guard<std::mutex> lock(_state_mutex);
    _state = new_state;
  }
  _state_cv.notify_all();
}

tor_stream::state tor_stream::get_state() const
{
  return _state.load();
}

bool tor_stream::wait_for_state(state desired_state, uint32_t timeout_ms)
{
  std::unique_lock<std::mutex> lock(_state_mutex);
  return _state_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
    [this, desired_state] { return _state.load() == desired_state; });
}

// Implementação de leitura bloqueante usando CRT
size_t tor_stream::read(void* buffer, size_t size)
{
  std::unique_lock<std::mutex> lock(_buffer_mutex);
  
  // Espera até ter dados ou o stream ser destruído
  _buffer_cv.wait(lock, [this] { 
    return !_buffer.empty() || get_state() == state::destroyed; 
  });

  if (_buffer.empty()) {
    return 0;
  }

  size_t size_to_copy = std::min(size, _buffer.size());
  std::memcpy(buffer, _buffer.data(), size_to_copy);

  // Remove os dados lidos do buffer (equivalente ao slice da mini)
  _buffer.erase(_buffer.begin(), _buffer.begin() + size_to_copy);

  // Se o buffer esvaziou, podemos sinalizar o envio de SENDME se necessário
  if (consider_sending_sendme()) {
    // _circuit->send_relay_sendme(this);
  }

  return size_to_copy;
}

size_t tor_stream::write(const void* buffer, size_t size)
{
  if (get_state() != state::ready) {
    return 0;
  }

  // No protocolo Tor, o write envia células RELAY_DATA através do circuito
  std::vector<uint8_t> data(static_cast<const uint8_t*>(buffer), 
                            static_cast<const uint8_t*>(buffer) + size);
  
  // O circuito cuidará da fragmentação em células de 498 bytes
  // _circuit->send_relay_data(this, data);

  return size;
}

void tor_stream::append_to_recv_buffer(const std::vector<uint8_t>& buffer)
{
  {
    std::lock_guard<std::mutex> lock(_buffer_mutex);
    _buffer.insert(_buffer.end(), buffer.begin(), buffer.end());
  }
  _buffer_cv.notify_one();
}

bool tor_stream::consider_sending_sendme()
{
  // Lógica de controle de fluxo simplificada
  if (_deliver_window <= (window_start - window_increment)) {
    _deliver_window += window_increment;
    return true;
  }
  return false;
}

void tor_stream::decrement_package_window() { _package_window--; }
void tor_stream::increment_package_window() { _package_window++; }
void tor_stream::decrement_deliver_window() { _deliver_window--; }

}