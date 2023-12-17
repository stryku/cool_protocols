#include "cool_protocols/formatters.hpp"
#include "cool_protocols/icmp.hpp"
#include "cool_protocols/ip.hpp"
#include "cool_protocols/utils.hpp"

#include <chrono>
#include <cstring>
#include <fmt/format.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <linux/ip.h>  /* for ipv4 header */
#include <linux/udp.h> /* for udp header */

#include <cstdint>
#include <stdexcept>

#define ADDR_TO_BIND "127.0.0.1"
#define PORT_TO_BIND 5555

#define MSG_SIZE 256
#define HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))

struct raii_socket {
  int socket = -1;
  ~raii_socket() {
    close(socket);
  }
};

raii_socket create_socket(int domain, int type, int protocol) {

  int raw_socket = socket(domain, type, protocol);

  if (raw_socket == -1) {
    fmt::print("socket error");
    throw std::runtime_error("socket error");
  }

  return raii_socket{raw_socket};
}

void do_bind(int s, const char *address, std::uint16_t port) {

  struct sockaddr_in sockstr;
  socklen_t socklen;

  sockstr.sin_family = AF_INET;
  sockstr.sin_port = cool_protocols::util::htons(port);
  sockstr.sin_addr.s_addr = inet_addr(address);
  socklen = (socklen_t)sizeof(sockstr);

  if (bind(s, (struct sockaddr *)&sockstr, socklen) == -1) {
    perror("bind");
    throw std::runtime_error("bind");
  }
}

struct ping_data {
  std::chrono::time_point<std::chrono::system_clock> m_sent_at;
} __attribute__((packed));

int main(void) {
  std::array<std::uint8_t, 1024> buffer;

  std::uint16_t identifier = 1337;

  std::string_view dest = "8.8.8.8";
  std::string_view src = "192.168.100.150";
  // std::string_view dest = "127.0.0.1";
  // std::string_view src = "127.0.0.1";
  bool verbose = true;

  raii_socket sock = create_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  raii_socket sock_recv = create_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  do_bind(sock_recv.socket, src.data(), 5555);

  // Send ping
  while (true) {

    ping_data data;
    data.m_sent_at = std::chrono::system_clock::now();

    cool_protocols::icmp::echo_message echo;
    echo.m_type = (std::uint8_t)cool_protocols::icmp::message_type::echo;
    echo.m_code = 0;
    echo.m_identifier = identifier++;
    echo.m_seq_number = 1;

    cool_protocols::util::detail::checksum_calculator calc;
    calc.add(echo.m_code, echo.m_type);
    calc.add(cool_protocols::util::htons(echo.m_identifier));
    calc.add(cool_protocols::util::htons(echo.m_seq_number));
    calc.add(cool_protocols::util::detail::as_bytes(data));

    echo.m_checksum = cool_protocols::util::ntohs(calc.finalize());

    // Prepare IP header
    cool_protocols::ip::internet_header ip_header;
    ip_header.m_version_and_length.set_version(4);
    ip_header.m_version_and_length.set_internet_header_length(
        cool_protocols::ip::k_internet_header_length_without_options / 4);
    ip_header.m_total_length =
        cool_protocols::ip::k_internet_header_length_without_options +
        sizeof(echo) + sizeof(data);
    ip_header.m_identification = identifier++;
    ip_header.m_time_to_live = 255;
    ip_header.m_protocol = (std::uint8_t)cool_protocols::ip::protocol::icmp;
    ip_header.m_source_address = cool_protocols::util::inet_addr(src);
    ip_header.m_destination_address = cool_protocols::util::inet_addr(dest);

    calc = {};
    calc.add(ip_header.m_version_and_length.m_value,
             ip_header.m_type_of_service.m_value);
    calc.add(ip_header.m_total_length);
    calc.add(ip_header.m_identification);
    calc.add(ip_header.m_flags_and_offset.m_value);
    calc.add(ip_header.m_time_to_live, ip_header.m_protocol);
    calc.add(ip_header.m_source_address);
    calc.add(ip_header.m_destination_address);

    ip_header.m_header_checksum = calc.finalize();

    if (verbose) {
      fmt::print("Sending ip header: {}\n", ip_header);
      fmt::print("Sending icmp echo: {}\n", echo);
    }

    // Make network order
    echo.m_identifier = cool_protocols::util::htons(echo.m_identifier);
    echo.m_seq_number = cool_protocols::util::htons(echo.m_seq_number);
    echo.m_checksum = cool_protocols::util::htons(echo.m_checksum);

    ip_header.m_total_length =
        cool_protocols::util::htons(ip_header.m_total_length);
    ip_header.m_identification =
        cool_protocols::util::htons(ip_header.m_identification);
    ip_header.m_flags_and_offset.m_value =
        cool_protocols::util::htons(ip_header.m_flags_and_offset.m_value);
    ip_header.m_header_checksum =
        cool_protocols::util::htons(ip_header.m_header_checksum);
    ip_header.m_source_address =
        cool_protocols::util::htonl(ip_header.m_source_address);
    ip_header.m_destination_address =
        cool_protocols::util::htonl(ip_header.m_destination_address);

    const std::span<const std::uint8_t> payload =
        cool_protocols::util::write_to_buffer(
            buffer,
            cool_protocols::util::detail::as_bytes(ip_header).subspan(
                0,
                cool_protocols::ip::k_internet_header_length_without_options),
            cool_protocols::util::detail::as_bytes(echo),
            cool_protocols::util::detail::as_bytes(data));

    // Send on socket
    sockaddr_in addrDest;
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(80);
    addrDest.sin_addr.s_addr = inet_addr(dest.data());

    if (verbose) {
      fmt::print("Sending {} bytes\n", payload.size());
    }

    fmt::print("Sending ping {} -> {}", src, dest);

    int sent_bytes = sendto(sock.socket, payload.data(), payload.size(), 0,
                            (struct sockaddr *)&addrDest, sizeof(sockaddr_in));
    if (sent_bytes == -1) {
      fmt::print("send error {}: {}\n", errno, strerror(errno));
      return 1;
    }

    // Receive pong

    while (true) {

      int recv_bytes = recv(sock_recv.socket, buffer.data(), buffer.size(), 0);
      if (recv_bytes == -1) {
        perror("recv");
        return 1;
      }

      const auto recv_at = std::chrono::system_clock::now();

      if (verbose) {
        fmt::print("Got {} bytes\n", recv_bytes);
      }

      std::span<const std::uint8_t> got_payload(buffer.data(), recv_bytes);

      const auto got_ip_header =
          cool_protocols::ip::read_internet_header(got_payload);

      if (verbose) {
        fmt::print("Got IP header: {}\n", got_ip_header.value());
      }

      std::span<const std::uint8_t> got_ip_payload = got_payload.subspan(
          got_ip_header->m_version_and_length.internet_header_length() * 4);

      const cool_protocols::icmp::message_type icmp_msg_type =
          cool_protocols::icmp::extract_message_type(got_ip_payload);

      if (icmp_msg_type != cool_protocols::icmp::message_type::echo_reply) {
        fmt::print("Not echo reply\n");
        continue;
      }

      const auto got_icmp_message =
          cool_protocols::icmp::read_echo_reply_message(got_ip_payload);
      const cool_protocols::icmp::host_order_echo_reply_message
          host_echo_reply =
              cool_protocols::icmp::ntoh(got_icmp_message->m_message);

      if (verbose) {
        fmt::print("Got ICMP header: {}\n", host_echo_reply.m_value);
      }

      ping_data recv_data;
      std::memcpy(&recv_data, got_icmp_message->m_data.data(),
                  sizeof(recv_data));

      std::chrono::duration<double> elapsed_seconds =
          recv_at - recv_data.m_sent_at;

      fmt::print("Got pong {} <- {}, rtt: {:.2}s\n", src, dest,
                 elapsed_seconds.count());
      std::this_thread::sleep_for(std::chrono::seconds{1});
      break;
    }
  }
  return 0;
}