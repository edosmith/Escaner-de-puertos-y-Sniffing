// JSONGen.cpp
// Responsable: Andres Tadeo Flores
#include "JSONGen.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iomanip>
#include <sstream>

using json = nlohmann::json;

static std::string bytes_to_hex_string(const std::vector<uint8_t>& b) {
    std::ostringstream oss;
    for (size_t i = 0; i < b.size(); ++i) {
        if (i) oss << " ";
        oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)b[i];
    }
    return oss.str();
}

bool write_json_results(const std::string& filename, const std::vector<FinalResult>& results) {
    json j = json::array();
    for (const auto& r : results) {
        json item;
        item["ip"] = r.ip;
        item["port"] = r.port;
        item["protocol"] = r.protocol;
        item["service"] = r.service;
        item["state"] = r.state;
        item["header_bytes"] = bytes_to_hex_string(r.header_bytes);
        j.push_back(item);
    }
    std::ofstream ofs(filename);
    if (!ofs) return false;
    ofs << std::setw(2) << j << std::endl;
    return true;
}
