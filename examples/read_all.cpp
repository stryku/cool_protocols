#include "cool_protocols/ip.hpp"
#include "cool_protocols/ip_fmt.hpp"

#include <fmt/format.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
  int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (raw_socket == -1) {
    fmt::print("Creating socket failed {}: {}\n", errno, strerror(errno));
    return 1;
  }

  //   int on = 1;
  //   if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
  //     fmt::print("Setting IP_HDRINCL failed\n");
  //     return 1;
  //   }

  sockaddr_in sockstr;
  sockstr.sin_family = AF_INET;
  sockstr.sin_port = htons(9999);
  sockstr.sin_addr.s_addr = inet_addr("127.0.0.1");
  const socklen_t socklen = sizeof(sockstr);

  /* use socklen instead sizeof()  Why had you defined socklen? :-)  */
  if (bind(raw_socket, (struct sockaddr *)&sockstr, socklen) == -1) {
    fmt::print("bind failed\n");
    return 1;
  }

  std::array<std::uint8_t, 1024> buffer;

  int read_size;
  if ((read_size = recv(raw_socket, buffer.data(), buffer.size(), 0)) == -1) {
    fmt::print("recv failed\n");
    return 1;
  }

  std::span<const std::uint8_t> read_buffer(buffer.data(), read_size);
  const auto header = cool_protocols::ip::read_internet_header(read_buffer);

  if (header.has_value()) {
    fmt::print("Got IP packet, header: {}", header.value());
  } else {
    fmt::print("Could not read IP packet, error: {}", header.error());
  }

  return 0;

  constexpr int k_max_events = 1000;
  struct epoll_event ev, events[k_max_events];
  int nfds, epollfd;

  /* Code to set up listening socket, 'listen_sock',
     (socket(), bind(), listen()) omitted. */

  epollfd = epoll_create1(0);
  if (epollfd == -1) {
    fmt::print("epoll_create1 failed\n");
    return 1;
  }

  ev.events = EPOLLIN;
  ev.data.fd = raw_socket;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_socket, &ev) == -1) {
    fmt::print("epoll_ctl: listen_sock failed\n");
    return 1;
  }

  for (;;) {
    nfds = epoll_wait(epollfd, events, k_max_events, -1);
    if (nfds == -1) {
      fmt::print("epoll_wait failed\n");
      return 1;
    }

    for (int n = 0; n < nfds; ++n) {
      if (events[n].data.fd == raw_socket) {

        int read_size = read(raw_socket, buffer.data(), buffer.size());
        if (read_size == -1) {
          fmt::print("failed reading socket\n");
        }

        std::span<const std::uint8_t> read_buffer(buffer.data(), read_size);
        const auto header =
            cool_protocols::ip::read_internet_header(read_buffer);

        if (header.has_value()) {
          fmt::print("Got IP packet, header: {}", header.value());
        } else {
          fmt::print("Could not read IP packet, error: {}", header.error());
        }

      } else {
        fmt::print("got different fd: {}\n", events[n].data.fd);
      }
    }
  }
}