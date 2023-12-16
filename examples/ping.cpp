// #include "cool_protocols/icmp.hpp"
// #include "cool_protocols/utils.hpp"

// #include <fmt/format.h>

// #include <arpa/inet.h>
// #include <netinet/in.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/socket.h>
// #include <sys/types.h>
// #include <unistd.h>

// #include <linux/ip.h>  /* for ipv4 header */
// #include <linux/udp.h> /* for udp header */

// #include <cstdint>
// #include <stdexcept>

// #define ADDR_TO_BIND "127.0.0.1"
// #define PORT_TO_BIND 5555

// #define MSG_SIZE 256
// #define HEADER_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))

// struct raii_socket {
//   int socket = -1;
//   ~raii_socket() {
//     close(socket);
//   }
// };

// raii_socket create_socket(int domain, int type, int protocol) {

//   int raw_socket = socket(domain, type, protocol);

//   if (raw_socket == -1) {
//     fmt::print("socket error");
//     throw std::runtime_error("socket error");
//   }

//   return raii_socket{raw_socket};
// }

// void do_bind(int s, const char *address, std::uint16_t port) {

//   struct sockaddr_in sockstr;
//   socklen_t socklen;

//   sockstr.sin_family = AF_INET;
//   sockstr.sin_port = cool_protocols::util::htons(port);
//   sockstr.sin_addr.s_addr = inet_addr(address);
//   socklen = (socklen_t)sizeof(sockstr);

//   if (bind(s, (struct sockaddr *)&sockstr, socklen) == -1) {
//     perror("bind");
//     throw std::runtime_error("bind");
//   }
// }

int main(void) {
  //   std::array<std::uint8_t, 1024> buffer;

  //   int retval = 0;

  //   /* do not use IPPROTO_RAW to receive packets */
  //   if ((raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
  //     perror("socket");
  //     return 1; /* here there is no clean up -- retval was not used */
  //   }

  //   raii_socket sock = create_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  //   do_bind(sock.socket, ADDR_TO_BIND, 5555);

  //   // Send ping
  //   cool_protocols::icmp::echo_message echo;
  //   echo.m_type = (std::uint8_t)cool_protocols::icmp::message_type::echo;
  //   echo.m_code = 0;
  //   echo.m_identifier = 1;
  //   echo.m_seq_number = 1;

  //   if ((msglen = recv(raw_socket, msg, MSG_SIZE, 0)) == -1) {
  //     perror("recv");
  //     retval = 1;
  //     goto _go_close_socket;
  //   }

  //   if (msglen <= (ssize_t)HEADER_SIZE) /* msg  can't be lesser than header!
  //   */
  //     printf("No msg!\n");
  //   else {
  //     msg[msglen - 1] = '\0'; /* we need a null character at the end*/
  //     printf("Your msg _plus_ headers's size is: %s\n", msg + HEADER_SIZE);
  //   }

  // _go_close_socket:

  //   return retval;
}