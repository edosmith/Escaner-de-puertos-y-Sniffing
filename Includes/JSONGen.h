// JSONGen.h
// Responsable: Andres Tadeo Flores
#ifndef JSONGEN_H
#define JSONGEN_H

#include <string>
#include <vector>
#include <cstdint>

struct FinalResult {
    std::string ip;
    int port;
    std::string protocol; // "TCP" o "UDP"
    std::string service;
    std::string state; // "Open"/"Closed"/"Filtered"/"Unknown"
    std::vector<uint8_t> header_bytes; // empty
};

bool write_json_results(const std::string& filename, const std::vector<FinalResult>& results);

#endif // JSONGEN_H
