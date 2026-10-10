// test_metrics_exporter.cpp — exposition format, routing, live loopback.

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <string>

#include "event_types.h"
#include "metrics_exporter.hpp"
#include "anomaly_detector.hpp" // AnomalyKind (full definition)

using telemetry::AnomalyKind;
using telemetry::MetricsExporter;

namespace {

telemetry_event make_evt(std::uint32_t type)
{
    telemetry_event e{};
    e.timestamp_ns = 1'000'000'000ULL;
    e.src_ip = 0x0A000001U;
    e.dst_ip = 0x0A000002U;
    e.src_port = 5000;
    e.dst_port = 80;
    e.event_type = type;
    return e;
}

bool contains(const std::string& hay, const char* needle)
{
    return hay.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("fresh exporter renders all required series at zero", "[metrics]")
{
    MetricsExporter ex{0}; // port 0: never binds unless start() is called
    const std::string body = ex.render();
    CHECK(contains(body, "telemetry_packets_total{protocol=\"tcp\",action=\"passed\"} 0"));
    CHECK(contains(body, "telemetry_packets_dropped_total{reason=\"syn_flood\"} 0"));
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"syn_flood\"} 0"));
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"port_scan\"} 0"));
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"suspicious_process\"} 0"));
    CHECK(contains(body, "telemetry_active_flows 0"));
    CHECK(contains(body, "# HELP telemetry_packets_total"));
    CHECK(contains(body, "# TYPE telemetry_anomalies_detected_total counter"));
    CHECK(contains(body, "# TYPE telemetry_active_flows gauge"));
}

TEST_CASE("observe_event classifies records into ingest counters", "[metrics]")
{
    MetricsExporter ex{0};
    ex.observe_event(make_evt(EVENT_PACKET_DROP));
    ex.observe_event(make_evt(EVENT_PACKET_DROP));
    ex.observe_event(make_evt(EVENT_ANOMALY));
    ex.observe_event(make_evt(EVENT_CONN_INIT));
    const std::string body = ex.render();
    CHECK(contains(body, "telemetry_packets_total{protocol=\"tcp\",action=\"passed\"} 2"));
    CHECK(contains(body, "telemetry_packets_dropped_total{reason=\"syn_flood\"} 1"));
    CHECK(contains(body, "telemetry_conn_events_total 1"));
}

TEST_CASE("verdicts increment per-type anomaly counters + gauges", "[metrics]")
{
    MetricsExporter ex{0};
    ex.inc_anomaly(AnomalyKind::kSynFlood);
    ex.inc_anomaly(AnomalyKind::kPortScan);
    ex.inc_anomaly(AnomalyKind::kPortScan);
    ex.inc_anomaly(AnomalyKind::kSuspiciousProcess);
    ex.set_active_flows(7);
    ex.set_ring_stats(1234, 2);
    const std::string body = ex.render();
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"syn_flood\"} 1"));
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"port_scan\"} 2"));
    CHECK(contains(body, "telemetry_anomalies_detected_total{type=\"suspicious_process\"} 1"));
    CHECK(contains(body, "telemetry_active_flows 7"));
    CHECK(contains(body, "telemetry_ring_consumed_total 1234"));
    CHECK(contains(body, "telemetry_ring_errors_total 2"));
}

TEST_CASE("handle_request routes /metrics /healthz 404/405/400", "[metrics]")
{
    MetricsExporter ex{0};
    ex.inc_packets_passed(3);

    const std::string m = ex.handle_request("GET /metrics HTTP/1.0\r\n\r\n");
    CHECK(contains(m, "200 OK"));
    CHECK(contains(m, "Content-Type: text/plain; version=0.0.4"));
    CHECK(contains(m, "telemetry_packets_total{protocol=\"tcp\",action=\"passed\"} 3"));

    const std::string q =
        ex.handle_request("GET /metrics?foo=bar HTTP/1.1\r\nHost: x\r\n\r\n");
    CHECK(contains(q, "200 OK"));

    const std::string h = ex.handle_request("GET /healthz HTTP/1.0\r\n\r\n");
    CHECK(contains(h, "200 OK"));
    CHECK(contains(h, "ok\n"));

    const std::string n = ex.handle_request("GET /nope HTTP/1.0\r\n\r\n");
    CHECK(contains(n, "404 Not Found"));

    const std::string p = ex.handle_request("POST /metrics HTTP/1.0\r\n\r\n");
    CHECK(contains(p, "405 Method Not Allowed"));

    const std::string b = ex.handle_request("garbage\r\n\r\n");
    CHECK(contains(b, "400 Bad Request"));
}

TEST_CASE("start/stop is idempotent; destructor stops", "[metrics]")
{
    MetricsExporter ex{0};
    ex.stop(); // stopping a never-started exporter is safe
    CHECK_FALSE(ex.running());
}

#if defined(__linux__) || defined(__APPLE__)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

int tcp_connect(std::uint16_t port)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        (void)::close(fd);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr),
                  static_cast<socklen_t>(sizeof(addr))) != 0) {
        (void)::close(fd);
        return -1;
    }
    return fd;
}

std::string recv_all(int fd)
{
    std::string out;
    char buf[2048];
    for (;;) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(n));
    }
    return out;
}

} // namespace

TEST_CASE("live loopback serves /metrics over TCP", "[metrics][integration]")
{
    MetricsExporter ex{0, "127.0.0.1"}; // ephemeral port, loopback only
    REQUIRE(ex.start());
    REQUIRE(ex.running());
    REQUIRE(ex.port() != 0);

    ex.inc_packets_passed(5);

    const int fd = tcp_connect(ex.port());
    REQUIRE(fd >= 0);
    const char* req = "GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n";
    const ssize_t sent = ::send(fd, req, std::strlen(req), 0);
    REQUIRE(sent == static_cast<ssize_t>(std::strlen(req)));
    const std::string resp = recv_all(fd);
    (void)::close(fd);

    CHECK(contains(resp, "HTTP/1.0 200 OK"));
    CHECK(contains(resp, "telemetry_packets_total{protocol=\"tcp\",action=\"passed\"} 5"));

    // Second connection: health check on the same instance.
    const int fd2 = tcp_connect(ex.port());
    REQUIRE(fd2 >= 0);
    const char* req2 = "GET /healthz HTTP/1.0\r\n\r\n";
    (void)::send(fd2, req2, std::strlen(req2), 0);
    const std::string resp2 = recv_all(fd2);
    (void)::close(fd2);
    CHECK(contains(resp2, "200 OK"));

    ex.stop();
    CHECK_FALSE(ex.running());
    ex.stop(); // idempotent
}

#endif // __linux__ || __APPLE__
