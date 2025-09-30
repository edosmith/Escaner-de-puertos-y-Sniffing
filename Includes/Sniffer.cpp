// Sniffer.cpp
// Responsable: Jorge Luis Casas
#include "Sniffer.h"
#include <pcap.h>
#include <cstring>
#include <thread>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

static bool started = false;

static inline std::string build_bpf(const std::string& ip, const std::vector<int>& ports) {
    
    std::string port_list;
    for (size_t i = 0; i < ports.size(); ++i) {
        if (!port_list.empty()) port_list += " or ";
        port_list += "src port " + std::to_string(ports[i]);
    }
    std::string filter = "(src host " + ip + ") and ( (tcp and (" + port_list + ")) or (udp and (" + port_list + ")) or icmp )";
    return filter;
}

static void process_packet(const u_char* packet, bpf_u_int32 caplen, int capture_first_n, const std::function<void(const CaptureResult&)>& on_capture) {
    
    if (caplen < 14 + sizeof(iphdr)) return;
    const u_char* ptr = packet + 14;
    const struct ip* iph = (const struct ip*)ptr;
    int ip_hdr_len = iph->ip_hl * 4;
    if (caplen < 14 + ip_hdr_len) return;

    CaptureResult res{};
    char srcbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, srcbuf, sizeof(srcbuf));
    res.ip = std::string(srcbuf);

    uint8_t proto = iph->ip_p;
    const u_char* transport = ptr + ip_hdr_len;
    int available = caplen - 14 - ip_hdr_len;
    int tocopy = std::min(capture_first_n, ip_hdr_len + std::max(0, available));
    
    res.header_bytes.assign(ptr, ptr + tocopy);

    if (proto == IPPROTO_TCP && available >= (int)sizeof(tcphdr)) {
        const struct tcphdr* th = (const struct tcphdr*)transport;
        res.port = ntohs(th->th_sport);
        res.protocol = "TCP";
        on_capture(res);
    } else if (proto == IPPROTO_UDP && available >= (int)sizeof(udphdr)) {
        const struct udphdr* uh = (const struct udphdr*)transport;
        res.port = ntohs(uh->uh_sport);
        res.protocol = "UDP";
        on_capture(res);
    } else if (proto == IPPROTO_ICMP) {
        const struct icmphdr* icmp = (const struct icmphdr*)transport;
        if (icmp->type == 3) {
            const u_char* inner = transport + 8;
            if (available >= 8 + (int)sizeof(struct ip)) {
                const struct ip* inner_ip = (const struct ip*)inner;
                int inner_ihl = inner_ip->ip_hl * 4;
                const u_char* inner_transport = inner + inner_ihl;
                if (inner_ip->ip_p == IPPROTO_UDP && (caplen >= (size_t)(14 + ip_hdr_len + 8 + inner_ihl + sizeof(udphdr)))) {
                    const struct udphdr* inner_udp = (const struct udphdr*)inner_transport;
                    res.port = ntohs(inner_udp->uh_dport);
                    res.protocol = "UDP";
                    int inner_available = caplen - (14 + ip_hdr_len + 8 + inner_ihl);
                    int inner_tocopy = std::min(capture_first_n, inner_ihl + std::max(0, inner_available));
                    res.header_bytes.assign(inner, inner + inner_tocopy);
                    on_capture(res);
                } else if (inner_ip->ip_p == IPPROTO_TCP && (caplen >= (size_t)(14 + ip_hdr_len + 8 + inner_ihl + sizeof(tcphdr)))) {
                    const struct tcphdr* inner_tcp = (const struct tcphdr*)inner_transport;
                    res.port = ntohs(inner_tcp->th_dport);
                    res.protocol = "TCP";
                    int inner_available = caplen - (14 + ip_hdr_len + 8 + inner_ihl);
                    int inner_tocopy = std::min(capture_first_n, inner_ihl + std::max(0, inner_available));
                    res.header_bytes.assign(inner, inner + inner_tocopy);
                    on_capture(res);
                }
            }
        }
    }
}
//Correcion ahora utiliza  atomic bool
bool start_sniffer_thread(const std::string& iface,
                          const std::string& target_ip,
                          const std::vector<int>& ports,
                          int capture_first_n,
                          std::function<void(const CaptureResult&)> on_capture,
                          std::atomic<bool>* stop_flag)
{
    if (started) return false;
    started = true;

    std::thread([=]() {
        char errbuf[PCAP_ERRBUF_SIZE];
        char* device = nullptr;
        pcap_if_t* alldevs = nullptr;

        std::string dev;
        if (!iface.empty()) {
            dev = iface;
        } else {
            device = pcap_lookupdev(errbuf);
            if (device == nullptr) {
                std::cerr << "pcap_lookupdev failed: " << errbuf << "\n";
                started = false;
                return;
            }
            dev = device;
        }

        pcap_t* handle = pcap_open_live(dev.c_str(), 65536, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live failed: " << errbuf << "\n";
            started = false;
            return;
        }

        std::string filter = build_bpf(target_ip, ports);
        bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "pcap_compile failed for filter: " << filter << "\n";
            pcap_close(handle);
            started = false;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "pcap_setfilter failed\n";
            pcap_freecode(&fp);
            pcap_close(handle);
            started = false;
            return;
        }
        pcap_freecode(&fp);

        while (!stop_flag->load()) {   // ✅ usar atomic load
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 1) {
                process_packet(packet, header->caplen, capture_first_n, on_capture);
            } else if (res == 0) {
                continue; // timeout
            } else if (res == -1) {
                std::cerr << "pcap_next_ex error: " << pcap_geterr(handle) << "\n";
                break;
            } else if (res == -2) {
                break; // EOF
            }
        }

        pcap_close(handle);
        started = false;
    }).detach();

    return true;
}

// Sniffer.cpp
