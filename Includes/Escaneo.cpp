// Escaneo.cpp
// Responsable: Eduardo Flores Smith
#include "Escaneo.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <cstring>
#include <errno.h>
#include <iostream>

static std::string port_service_hint(int port, const std::string& proto) {
    // 
    if (proto == "TCP") {
        if (port == 22) return "ssh";
        if (port == 80) return "http";
        if (port == 443) return "https";
        if (port == 3306) return "mysql";
        if (port == 21) return "ftp";
    } else {
        if (port == 161) return "snmp";
        if (port == 53) return "dns";
        if (port == 123) return "ntp";
    }
    return "unknown";
}

static std::string tcp_probe(const std::string& ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "Unknown";

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int res = connect(sock, (sockaddr*)&addr, sizeof(addr));
    if (res == 0) {
        close(sock);
        return "Open";
    } else {
        if (errno != EINPROGRESS) { // error
            if (errno == ECONNREFUSED) {
                close(sock);
                return "Closed";
            }
            // filtered/closed
        } else {
            // wait
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(sock, &wf);
            timeval tv{};
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int s = select(sock + 1, nullptr, &wf, nullptr, &tv);
            if (s > 0 && FD_ISSET(sock, &wf)) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                    close(sock);
                    return "Unknown";
                }
                if (err == 0) {
                    close(sock);
                    return "Open";
                } else if (err == ECONNREFUSED) {
                    close(sock);
                    return "Closed";
                } else {
                    close(sock);
                    return "Filtered";
                }
            } else {
                // timeout
                close(sock);
                return "Filtered";
            }
        }
    }
    close(sock);
    return "Unknown";
}

static std::string udp_probe(const std::string& ip, int port, int timeout_ms) {
    // we send an empty datagram and rely on ICMP unreachable.
    // Here we mark UDP as "Unknown" initially and let sniffer update to Open/Closed when it sees responses.
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "Unknown";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // send zero bytes
    ssize_t sent = sendto(sock, nullptr, 0, 0, (sockaddr*)&addr, sizeof(addr));
    (void)sent;
    close(sock);
    // mark as "Filtered" by default; sniffer may set "Closed" if it sees ICMP unreachable or "Open" if sees payload.
    return "Filtered";
}

void start_scanner(const std::string& target_ip,
                   const std::vector<int>& ports,
                   int timeout_ms,
                   unsigned int concurrency,
                   ScanCallback cb)
{
    // Thread pool with a queue of ScanTask
    std::queue<ScanTask> q;
    std::mutex q_m;
    std::condition_variable q_cv;
    bool finished_push = false;

    // push tasks: for both TCP and UDP for each port
    for (int p : ports) {
        ScanTask tTcp{target_ip, p, "TCP", timeout_ms};
        ScanTask tUdp{target_ip, p, "UDP", timeout_ms};
        q.push(tTcp);
        q.push(tUdp);
    }

    finished_push = true;

    auto worker = [&]() {
        while (true) {
            ScanTask task;
            {
                std::unique_lock<std::mutex> lk(q_m);
                if (q.empty()) break;
                task = q.front(); q.pop();
            }
            std::string state = "Unknown";
            if (task.protocol == "TCP") {
                state = tcp_probe(task.ip, task.port, task.timeout_ms);
            } else {
                state = udp_probe(task.ip, task.port, task.timeout_ms);
            }
            // Callback with the state determined by the scanner.
            cb(task, state);
        }
    };

    std::vector<std::thread> threads;
    unsigned int nthreads = concurrency ? concurrency : 4;
    for (unsigned int i = 0; i < nthreads; ++i) threads.emplace_back(worker);
    for (auto& t : threads) if (t.joinable()) t.join();
}

//end escaneo.cpp
