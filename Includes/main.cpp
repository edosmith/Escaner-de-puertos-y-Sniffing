// main.cpp
// Responsable: Eduardo Marcador
#include "Escaneo.h"
#include "Sniffer.h"
#include "JSONGen.h"
#include <iostream>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <sstream>

// Simple mapping port->service
static std::string service_hint(int port, const std::string& proto) {
    if (proto == "TCP") {
        if (port == 22) return "ssh";
        if (port == 80) return "http";
        if (port == 443) return "https";
        if (port == 21) return "ftp";
    } else {
        if (port == 161) return "snmp";
        if (port == 53) return "dns";
        if (port == 123) return "ntp";
    }
    return "unknown";
}

int main() {
    std::string target_ip;
    std::cout << "IP objetivo: ";
    std::getline(std::cin, target_ip);

    std::string ports_input;
    std::cout << "Puertos (rango 'start-end' o lista '22,80,161'): ";
    std::getline(std::cin, ports_input);
    std::vector<int> ports;
    if (ports_input.find('-') != std::string::npos) {
        int a, b;
        char dash;
        std::istringstream iss(ports_input);
        iss >> a >> dash >> b;
        if (a > 0 && b >= a) {
            for (int p = a; p <= b; ++p) ports.push_back(p);
        }
    } else {
        std::istringstream iss(ports_input);
        std::string token;
        while (std::getline(iss, token, ',')) {
            int p = std::stoi(token);
            ports.push_back(p);
        }
    }

    std::string timeout_s;
    std::cout << "Timeout (ms) [default 500]: ";
    std::getline(std::cin, timeout_s);
    int timeout_ms = 500;
    if (!timeout_s.empty()) timeout_ms = std::stoi(timeout_s);

    std::string outname;
    std::cout << "Nombre archivo JSON salida [resultado.json]: ";
    std::getline(std::cin, outname);
    if (outname.empty()) outname = "resultado.json";

    std::string iface;
    std::cout << "Interfaz pcap (vacío para auto): ";
    std::getline(std::cin, iface);

    unsigned int concurrency = std::thread::hardware_concurrency();
    if (!concurrency) concurrency = 4;

    std::cout << "Iniciando sniffer en background..." << std::endl;

    // Shared structures between scanner and sniffer
    struct Key { std::string proto; int port; };
    struct KeyHash { size_t operator()(Key const& k) const noexcept { return std::hash<std::string>()(k.proto) ^ std::hash<int>()(k.port); } };
    struct KeyEq { bool operator()(Key const& a, Key const& b) const noexcept { return a.proto==b.proto && a.port==b.port; } };

    // Map: proto+port -> FinalResult
    std::unordered_map<std::string, FinalResult> results_map;
    std::mutex results_mtx;

    auto make_key = [](const std::string& proto, int port) {
        return proto + ":" + std::to_string(port);
    };

    // Initialize map entries from ports
    for (int p : ports) {
        // TCP
        FinalResult fr;
        fr.ip = target_ip;
        fr.port = p;
        fr.protocol = "TCP";
        fr.service = service_hint(p, "TCP");
        fr.state = "Unknown";
        fr.header_bytes = {};
        results_map[make_key("TCP", p)] = fr;
        // UDP
        FinalResult fr2;
        fr2.ip = target_ip;
        fr2.port = p;
        fr2.protocol = "UDP";
        fr2.service = service_hint(p, "UDP");
        fr2.state = "Unknown";
        fr2.header_bytes = {};
        results_map[make_key("UDP", p)] = fr2;
    }

    std::atomic<bool> stop_sniffer(false);

    // On capture callback: update results_map
    auto on_capture = [&](const CaptureResult& cap) {
        std::lock_guard<std::mutex> lk(results_mtx);
        std::string k = make_key(cap.protocol, cap.port);
        auto it = results_map.find(k);
        if (it != results_map.end()) {
            // If we haven't already a header, store first seen header bytes and mark open
            if (it->second.header_bytes.empty()) {
                it->second.header_bytes = cap.header_bytes;
                it->second.state = "Open";
            }
        } else {
            // not found: create entry
            FinalResult fr;
            fr.ip = cap.ip;
            fr.port = cap.port;
            fr.protocol = cap.protocol;
            fr.service = service_hint(cap.port, cap.protocol);
            fr.state = "Open";
            fr.header_bytes = cap.header_bytes;
            results_map[k] = fr;
        }
    };

    bool ok = start_sniffer_thread(iface, target_ip, ports, 16, on_capture, &stop_sniffer);
    if (!ok) {
        std::cerr << "Error iniciando sniffer. Asegúrate de tener libpcap y permisos (root).\n";
        return 1;
    }

    // Scanner callback updates results_map with scanner-determined state (if sniffer hasn't set Open)
    auto scanner_cb = [&](const ScanTask& task, const std::string& state) {
        std::lock_guard<std::mutex> lk(results_mtx);
        std::string k = make_key(task.protocol, task.port);
        auto it = results_map.find(k);
        if (it == results_map.end()) {
            FinalResult fr;
            fr.ip = task.ip;
            fr.port = task.port;
            fr.protocol = task.protocol;
            fr.service = service_hint(task.port, task.protocol);
            fr.state = state;
            fr.header_bytes = {};
            results_map[k] = fr;
        } else {
            // Only set state if it's Unknown or Filtered (prefer "Open" from sniffer)
            if (it->second.state == "Unknown" || it->second.state == "Filtered") {
                it->second.state = state;
            }
        }
        // Print minimal console info
        std::cout << task.protocol << " " << task.port << " -> " << state << std::endl;
    };

    std::cout << "Iniciando escaneo (concurrency=" << concurrency << ")..." << std::endl;
    start_scanner(target_ip, ports, timeout_ms, concurrency, scanner_cb);

    // Allow some time for sniffer to collect late responses for a short grace period
    std::cout << "Escaneo terminado. esperando 2 segundos para capturas tardías..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // stop sniffer
    stop_sniffer = true;
    // Grace wait for sniffer thread to finish (it checks the flag periodically)
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Prepare vector results
    std::vector<FinalResult> final_results;
    {
        std::lock_guard<std::mutex> lk(results_mtx);
        for (auto& kv : results_map) {
            final_results.push_back(kv.second);
        }
    }

    bool wrote = write_json_results(outname, final_results);
    if (!wrote) {
        std::cerr << "Error escribiendo archivo JSON " << outname << std::endl;
        return 1;
    }

    std::cout << "Resultados escritos en " << outname << std::endl;
    return 0;
}
