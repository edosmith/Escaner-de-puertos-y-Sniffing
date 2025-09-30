// Sniffer.h
// Responsable: Jorge Luis Casas
#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <atomic>

struct CaptureResult {
    std::string ip;
    int port;
    std::string protocol; // "TCP" o "UDP"
    std::vector<uint8_t> header_bytes; //IP+transport header
};

bool start_sniffer_thread(const std::string& iface,
                          const std::string& target_ip,
                          const std::vector<int>& ports,
                          int capture_first_n,
                          std::function<void(const CaptureResult&)> on_capture,
                          std::atomic<bool>* stop_flag);

#endif // SNIFFER_H





