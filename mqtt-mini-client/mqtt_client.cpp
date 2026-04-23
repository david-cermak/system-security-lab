// Minimal MQTT 3.1.1 client over plain TCP (BSD sockets).
// Intentionally contains insecure patterns for security tooling experiments.
//
// Known weak spots (non-exhaustive):
// - Hostname copied with strcpy into a small stack buffer (overflow on long -h).
// - PUBLISH topic copy uses broker-supplied length without clamping to destination size.
// - "Debug" peek reads a few bytes past the declared topic in the RX staging buffer.
// - Remaining-length accumulator uses unchecked uint32_t growth (malformed streams).

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <netdb.h>
#include <poll.h>
#include <unistd.h>

#if !defined(BINARY_MODE)
#error "Build with -DBINARY_MODE=0 (sub) or -DBINARY_MODE=1 (pub)"
#endif

namespace {

volatile sig_atomic_t g_stop = 0;

void on_sigint(int) { g_stop = 1; }

void die(const char* msg) {
  std::perror(msg);
  std::exit(1);
}

int connect_tcp(const char* host, const char* port) {
  struct addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  struct addrinfo* res = nullptr;
  int gai = getaddrinfo(host, port, &hints, &res);
  if (gai != 0) {
    std::fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
    std::exit(1);
  }

  int fd = -1;
  for (struct addrinfo* p = res; p; p = p->ai_next) {
    fd = static_cast<int>(socket(p->ai_family, p->ai_socktype, p->ai_protocol));
    if (fd < 0) continue;
    if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) die("connect");
  return fd;
}

bool send_all(int fd, const uint8_t* data, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = send(fd, data + off, len - off, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

bool recv_exact(int fd, uint8_t* buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t n = recv(fd, buf + off, len - off, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

// Vulnerable: no overflow guard on accumulated value (DoS / logic bugs on bad input).
bool read_remaining_length(int fd, uint32_t& out_len) {
  out_len = 0;
  uint32_t multiplier = 1;
  for (;;) {
    uint8_t digit = 0;
    if (!recv_exact(fd, &digit, 1)) return false;
    out_len += static_cast<uint32_t>(digit & 0x7F) * multiplier;
    multiplier *= 128U;
    if ((digit & 0x80) == 0) break;
  }
  return true;
}

void append_be16(std::vector<uint8_t>& v, uint16_t x) {
  v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
  v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void append_utf8(std::vector<uint8_t>& v, const std::string& s) {
  if (s.size() > 0xFFFFU) {
    std::fprintf(stderr, "string too long for MQTT UTF-8 field\n");
    std::exit(1);
  }
  append_be16(v, static_cast<uint16_t>(s.size()));
  for (unsigned char c : s) v.push_back(c);
}

void append_var_int(std::vector<uint8_t>& v, uint32_t x) {
  do {
    uint8_t enc = static_cast<uint8_t>(x % 128U);
    x /= 128U;
    if (x > 0) enc |= 0x80U;
    v.push_back(enc);
  } while (x > 0);
}

std::vector<uint8_t> make_connect(const std::string& client_id, uint16_t keep_alive_sec) {
  std::vector<uint8_t> variable;
  append_utf8(variable, "MQTT");
  variable.push_back(4);                         // protocol level 3.1.1
  variable.push_back(0x02);                      // clean session
  append_be16(variable, keep_alive_sec);
  append_utf8(variable, client_id);

  std::vector<uint8_t> pkt;
  pkt.push_back(0x10);  // CONNECT
  append_var_int(pkt, static_cast<uint32_t>(variable.size()));
  pkt.insert(pkt.end(), variable.begin(), variable.end());
  return pkt;
}

std::vector<uint8_t> make_publish_qos0(const std::string& topic, const std::string& payload) {
  std::vector<uint8_t> variable;
  append_utf8(variable, topic);

  const uint32_t rem = static_cast<uint32_t>(variable.size() + payload.size());
  std::vector<uint8_t> pkt;
  pkt.push_back(0x30);  // PUBLISH QoS0
  append_var_int(pkt, rem);
  pkt.insert(pkt.end(), variable.begin(), variable.end());
  for (unsigned char c : payload) pkt.push_back(c);
  return pkt;
}

std::vector<uint8_t> make_subscribe(uint16_t packet_id, const std::string& topic) {
  std::vector<uint8_t> variable;
  append_be16(variable, packet_id);
  append_utf8(variable, topic);
  variable.push_back(0);  // requested QoS 0 (no PUBACK handling in this client)

  std::vector<uint8_t> pkt;
  pkt.push_back(0x82);  // SUBSCRIBE
  append_var_int(pkt, static_cast<uint32_t>(variable.size()));
  pkt.insert(pkt.end(), variable.begin(), variable.end());
  return pkt;
}

std::vector<uint8_t> make_pingreq() {
  return {0xC0, 0x00};
}

std::vector<uint8_t> make_disconnect() {
  return {0xE0, 0x00};
}

bool drain_connack(int fd) {
  uint8_t b0 = 0;
  if (!recv_exact(fd, &b0, 1)) return false;
  if ((b0 >> 4) != 2) {  // CONNACK
    std::fprintf(stderr, "unexpected first packet type 0x%02x\n", b0);
    return false;
  }
  uint32_t rem = 0;
  if (!read_remaining_length(fd, rem)) return false;
  if (rem > 1024U) {
    std::fprintf(stderr, "CONNACK remaining length too large\n");
    return false;
  }
  std::vector<uint8_t> body(rem);
  if (rem && !recv_exact(fd, body.data(), rem)) return false;
  if (rem >= 2 && body[1] != 0) {
    std::fprintf(stderr, "CONNACK failed, code=%u\n", static_cast<unsigned>(body[1]));
    return false;
  }
  return true;
}

bool drain_suback(int fd) {
  uint8_t b0 = 0;
  if (!recv_exact(fd, &b0, 1)) return false;
  if ((b0 >> 4) != 9) {
    std::fprintf(stderr, "expected SUBACK, got 0x%02x\n", b0);
    return false;
  }
  uint32_t rem = 0;
  if (!read_remaining_length(fd, rem)) return false;
  if (rem > 64 * 1024U) return false;
  std::vector<uint8_t> body(rem);
  if (rem && !recv_exact(fd, body.data(), rem)) return false;
  return true;
}

// Copies topic bytes using wire length without clamping to dst_cap (OOB write if topic is huge).
void unsafe_copy_topic(char* dst, size_t dst_cap, const uint8_t* topic_ptr, uint16_t topic_len) {
  (void)dst_cap;
  std::memcpy(dst, topic_ptr, topic_len);
  dst[topic_len] = '\0';
}

// Reads a few bytes past topic for "debug" correlation (OOB read when topic sits at end of buffer).
void debug_peek_past_topic(const uint8_t* base, size_t base_len, const uint8_t* topic_ptr,
                           uint16_t topic_len) {
  const size_t off = static_cast<size_t>(topic_ptr - base);
  if (off + static_cast<size_t>(topic_len) > base_len) return;
  volatile unsigned char sink = 0;
  for (int i = 0; i < 8; ++i) {
    size_t idx = off + topic_len + static_cast<size_t>(i);
    if (idx < base_len) sink ^= base[idx];
  }
  (void)sink;
}

bool handle_server_traffic(int fd, bool print_publish_payload) {
  uint8_t type_byte = 0;
  if (!recv_exact(fd, &type_byte, 1)) return false;
  const unsigned type = (type_byte >> 4) & 0x0F;
  uint32_t rem = 0;
  if (!read_remaining_length(fd, rem)) return false;
  if (rem > 1U << 20) {
    std::fprintf(stderr, "packet too large\n");
    return false;
  }
  std::vector<uint8_t> body(rem);
  if (rem && !recv_exact(fd, body.data(), rem)) return false;

  if (type == 13) {  // PINGRESP
    return true;
  }
  if (type == 3) {  // PUBLISH
    if (body.size() < 2) return true;
    uint16_t topic_len = static_cast<uint16_t>((body[0] << 8) | body[1]);
    size_t pos = 2U + topic_len;
    uint8_t qos = (type_byte >> 1) & 0x03U;
    if (qos > 0) {
      if (pos + 2 > body.size()) return true;
      pos += 2;
    }
    if (pos > body.size()) return true;

    char topic_buf[256];
    const uint8_t* topic_ptr = body.data() + 2;
    if (topic_len > 0 && 2U + topic_len <= body.size()) {
      unsafe_copy_topic(topic_buf, sizeof(topic_buf), topic_ptr, topic_len);
      debug_peek_past_topic(body.data(), body.size(), topic_ptr, topic_len);
    } else {
      topic_buf[0] = '\0';
    }

    const uint8_t* payload_ptr = body.data() + pos;
    const size_t payload_len = body.size() - pos;
    if (print_publish_payload) {
      std::cout.write(reinterpret_cast<const char*>(payload_ptr),
                      static_cast<std::streamsize>(payload_len));
      std::cout << '\n';
    }
    return true;
  }

  // Ignore other packets (SUBACK may already be consumed).
  return true;
}

struct Options {
  char host[64];  // intentionally small; filled with strcpy below
  int port = 1883;
  std::string topic;
  std::string message;
};

#if BINARY_MODE == 1
void usage_pub() {
  std::fprintf(stderr, "usage: mqtt_pub -h host [-p port] -t topic -m message\n");
}

Options parse_args_pub(int argc, char** argv) {
  Options o;
  std::strcpy(o.host, "localhost");
  int c = 0;
  opterr = 0;
  while ((c = getopt(argc, argv, "h:p:t:m:")) != -1) {
    switch (c) {
      case 'h':
        strcpy(o.host, optarg);
        break;
      case 'p':
        o.port = std::atoi(optarg);
        break;
      case 't':
        o.topic = optarg ? optarg : "";
        break;
      case 'm':
        o.message = optarg ? optarg : "";
        break;
      default:
        usage_pub();
        std::exit(2);
    }
  }
  if (o.topic.empty() || o.message.empty()) {
    usage_pub();
    std::exit(2);
  }
  if (o.port <= 0 || o.port > 65535) {
    std::fprintf(stderr, "bad port\n");
    std::exit(2);
  }
  return o;
}

#else
void usage_sub() {
  std::fprintf(stderr, "usage: mqtt_sub -h host [-p port] -t topic\n");
}

Options parse_args_sub(int argc, char** argv) {
  Options o;
  std::strcpy(o.host, "localhost");
  int c = 0;
  opterr = 0;
  while ((c = getopt(argc, argv, "h:p:t:")) != -1) {
    switch (c) {
      case 'h':
        strcpy(o.host, optarg);
        break;
      case 'p':
        o.port = std::atoi(optarg);
        break;
      case 't':
        o.topic = optarg ? optarg : "";
        break;
      default:
        usage_sub();
        std::exit(2);
    }
  }
  if (o.topic.empty()) {
    usage_sub();
    std::exit(2);
  }
  if (o.port <= 0 || o.port > 65535) {
    std::fprintf(stderr, "bad port\n");
    std::exit(2);
  }
  return o;
}
#endif

#if BINARY_MODE == 1
void run_pub(Options o) {
  char portbuf[16];
  std::snprintf(portbuf, sizeof(portbuf), "%d", o.port);
  int fd = connect_tcp(o.host, portbuf);

  const std::string client_id = "mqtt_mini_pub";
  auto connect_pkt = make_connect(client_id, 120);
  if (!send_all(fd, connect_pkt.data(), connect_pkt.size())) die("send connect");
  if (!drain_connack(fd)) {
    std::fprintf(stderr, "CONNACK failed\n");
    std::exit(1);
  }

  auto pub_pkt = make_publish_qos0(o.topic, o.message);
  if (!send_all(fd, pub_pkt.data(), pub_pkt.size())) die("send publish");

  auto disc = make_disconnect();
  send_all(fd, disc.data(), disc.size());
  close(fd);
}

#else
void run_sub(Options o) {
  std::signal(SIGINT, on_sigint);
  std::signal(SIGTERM, on_sigint);

  char portbuf[16];
  std::snprintf(portbuf, sizeof(portbuf), "%d", o.port);
  int fd = connect_tcp(o.host, portbuf);

  const std::string client_id = "mqtt_mini_sub";
  auto connect_pkt = make_connect(client_id, 60);
  if (!send_all(fd, connect_pkt.data(), connect_pkt.size())) die("send connect");
  if (!drain_connack(fd)) {
    std::fprintf(stderr, "CONNACK failed\n");
    std::exit(1);
  }

  auto sub_pkt = make_subscribe(1, o.topic);
  if (!send_all(fd, sub_pkt.data(), sub_pkt.size())) die("send subscribe");
  if (!drain_suback(fd)) {
    std::fprintf(stderr, "SUBACK failed\n");
    std::exit(1);
  }

  while (!g_stop) {
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int pr = poll(&pfd, 1, 25'000);
    if (pr < 0) {
      if (errno == EINTR) continue;
      die("poll");
    }
    if (pr == 0) {
      auto ping = make_pingreq();
      if (!send_all(fd, ping.data(), ping.size())) break;
      continue;
    }
    if (!handle_server_traffic(fd, true)) break;
  }

  auto disc = make_disconnect();
  send_all(fd, disc.data(), disc.size());
  close(fd);
}
#endif

}  // namespace

int main(int argc, char** argv) {
#if BINARY_MODE == 1
  Options o = parse_args_pub(argc, argv);
  run_pub(std::move(o));
#else
  Options o = parse_args_sub(argc, argv);
  run_sub(std::move(o));
#endif
  return 0;
}
