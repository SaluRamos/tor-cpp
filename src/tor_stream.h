#pragma once
#include "common.h"

#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace tor {

class circuit;

// Removida a herança de io::stream da mini. 
// Implementamos uma interface de stream compatível com a CRT.
class tor_stream
{
  public:
    tor_stream(
      tor_stream_id_type stream_id,
      circuit* circuit
      );

    ~tor_stream();

    void close();

    // Métodos de IO padrão
    size_t read(void* buffer, size_t size);
    size_t write(const void* buffer, size_t size);

    tor_stream_id_type get_stream_id() const;

    enum class state
    {
      none,
      connecting,
      ready,
      destroyed,
    };

  private:
    friend class circuit;

    void append_to_recv_buffer(const std::vector<uint8_t>& buffer);
    
    state get_state() const;
    void set_state(state new_state);
    
    bool wait_for_state(state desired_state, uint32_t timeout_ms = 30000);

    // Controle de fluxo (Tor protocol)
    void decrement_package_window();
    void increment_package_window();
    void decrement_deliver_window();
    bool consider_sending_sendme();

    static constexpr size_t window_start = 500;
    static constexpr size_t window_increment = 50;
    static constexpr size_t window_max_unflushed = 10;

    tor_stream_id_type _stream_id;
    circuit* _circuit;

    // Buffer e Sincronização CRT
    std::vector<uint8_t> _buffer;
    mutable std::mutex _buffer_mutex;
    std::condition_variable _buffer_cv;

    std::atomic<state> _state{state::none};
    mutable std::mutex _state_mutex;
    std::condition_variable _state_cv;

    // Janelas de fluxo
    int _package_window = window_start;
    int _deliver_window = window_start;
};

}