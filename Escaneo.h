// Escaneo.h
// Responsable: Eduardo Flores Smith
#ifndef ESCANEO_H
#define ESCANEO_H

#include <string>
#include <vector>
#include <functional>

struct ScanTask {
    std::string ip;
    int port;
    std::string protocol; // "TCP" or "UDP"
    int timeout_ms;
};

using ScanCallback = std::function<void(const ScanTask&, const std::string& state)>;
// state: "Open", "Closed", "Filtered", "Unknown"

void start_scanner(const std::string& target_ip,
                   const std::vector<int>& ports,
                   int timeout_ms,
                   unsigned int concurrency,
                   ScanCallback cb);

#endif // ESCANEO_H
