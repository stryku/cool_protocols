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
#include <unistd.h>

#include <linux/ip.h>  /* for ipv4 header */
#include <linux/udp.h> /* for udp header */

#include <cstdint>
#include <stdexcept>

#define ADDR_TO_BIND "127.0.0.1"
#define PORT_TO_BIND 5555

#define MSG_SIZE 256
#define HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))

struct ping_data {
  std::chrono::time_point<std::chrono::system_clock> m_sent_at;
} __attribute__((packed));

void dump(std::span<const std::uint8_t> data) {
  for (auto d : data) {
    fmt::print("{:x} ", d);
  }
}

int main(void) {
  std::array<std::uint8_t, 1024> buffer;

  // Send ping

  ping_data data;
  data.m_sent_at = std::chrono::system_clock::now();
  // data.m_sent_at = {};

  cool_protocols::icmp::echo_message echo;
  echo.m_type = (std::uint8_t)cool_protocols::icmp::message_type::echo;
  echo.m_code = 0;
  echo.m_identifier = 1;
  echo.m_seq_number = 1;

  cool_protocols::util::detail::checksum_calculator calc;
  calc.add(echo.m_type, echo.m_code);
  calc.add(echo.m_identifier);
  calc.add(echo.m_seq_number);
  calc.add(cool_protocols::util::detail::as_bytes(data));

  echo.m_checksum = calc.finalize();

  // Prepare IP header
  cool_protocols::ip::internet_header ip_header;
  ip_header.m_version_and_length.set_version(4);
  ip_header.m_version_and_length.set_internet_header_length(
      cool_protocols::ip::k_internet_header_length_without_options / 4);
  ip_header.m_total_length =
      cool_protocols::ip::k_internet_header_length_without_options +
      sizeof(echo) + sizeof(data);
  ip_header.m_identification = 1337;
  ip_header.m_time_to_live = 255;
  ip_header.m_protocol = (std::uint8_t)cool_protocols::ip::protocol::icmp;
  ip_header.m_source_address =
      cool_protocols::util::inet_addr("192.168.100.150");
  ip_header.m_destination_address = cool_protocols::util::inet_addr("8.8.8.8");
  // ip_header.m_source_address = cool_protocols::util::inet_addr("127.0.0.1");
  // ip_header.m_destination_address =
  //     cool_protocols::util::inet_addr("127.0.0.1");

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

  fmt::print("Sending ip header: {}\n", ip_header);
  fmt::print("Sending icmp echo: {}\n", echo);

  // sockaddr addr;
  // addr.sa_family = AF_INET;
  // inet_pton(AF_INET, "8.8.8.8", &addr.sa_data);

  // std::memcpy(addr.sa_data, &ip_header.m_destination_address,
  //             sizeof(ip_header.m_destination_address));

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
              0, cool_protocols::ip::k_internet_header_length_without_options),
          cool_protocols::util::detail::as_bytes(echo),
          cool_protocols::util::detail::as_bytes(data));

  sockaddr_in addrDest;
  addrDest.sin_family = AF_INET;
  addrDest.sin_port = htons(80);
  addrDest.sin_addr.s_addr = inet_addr("8.8.8.8");

  fmt::print("Sending {} bytes\n", payload.size());
  dump(payload);

  //   int sent_bytes = sendto(sock.socket, payload.data(), payload.size(), 0,
  //                           (struct sockaddr *)&addrDest,
  //                           sizeof(sockaddr_in));
  //   if (sent_bytes == -1) {
  //     fmt::print("send error {}: {}\n", errno, strerror(errno));
  //     return 1;
  //   }

  //   // Receive pong
  //   do_bind(sock.socket, ADDR_TO_BIND, 5555);

  //   int recv_bytes = recv(sock.socket, buffer.data(), buffer.size(), 0);
  //   if (recv_bytes == -1) {
  //     perror("recv");
  //     return 1;
  //   }

  //   fmt::print("Got {} bytes", recv_bytes);

  return 0;
}