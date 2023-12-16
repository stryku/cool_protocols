#pragma once

#include "utils.hpp"

#include <array>
#include <atomic>
#include <bit>
#include <cassert>
#include <expected>
#include <span>

namespace cool_protocols::icmp {

enum class message_type : std::uint8_t {
  echo_reply = 0,
  destination_unreachable = 3,
  source_quench = 4,
  redirect = 5,
  echo = 8,
  time_exceeded = 11,
  parameter_problem = 12,
  timestamp = 13,
  timestamp_reply = 14,
  information_request = 15,
  information_reply = 16
};

enum class message_reading_error { no_enough_data };

struct echo_message {
  std::uint8_t m_type = 0;
  std::uint8_t m_code = 0;
  std::uint16_t m_checksum = 0;
  std::uint16_t m_identifier = 0;
  std::uint16_t m_seq_number = 0;
} __attribute__((packed));

inline std::uint16_t calc_checksum(std::span<const std::uint8_t> data) {

  std::uint32_t checksum = 0;

  const auto add_overflow = [&checksum] {
    while (checksum & 0xff'ff'00'00) {
      const std::uint16_t overflow = checksum >> 16;
      checksum &= 0xff'ff;
      checksum += overflow;
    }
  };

  for (unsigned i = 0; i < data.size(); i += sizeof(std::uint16_t)) {
    std::uint16_t ui;
    std::memcpy(&ui, &data[i], sizeof(std::uint16_t));
    checksum += ui;
    add_overflow();
  }
  checksum = util::ntohs(checksum);

  if (data.size() % 2 == 1) {
    const std::uint16_t ui = ((std::uint16_t)data.back()) << 8;
    checksum += ui;
    add_overflow();
  }

  return ~checksum;
}

template <typename T>
inline std::uint16_t calc_checksum(const T &msg,
                                   std::span<const std::uint8_t> data) {

  static_assert(sizeof(T) % 2 == 0);

  using msg_array_t = std::array<const std::uint8_t, sizeof(msg)>;

  const msg_array_t msg_array = std::bit_cast<msg_array_t>(msg);
  //   std::uint32_t checksum = ~calc_checksum(msg_array);
  //   checksum += ~calc_checksum(data);
  //   while (checksum & 0xff'ff'00'00) {
  //     const std::uint16_t overflow = checksum >> 16;
  //     checksum &= 0xff'ff;
  //     checksum += overflow;
  //   }

  //   return ~checksum;

  std::uint32_t checksum = 0;

  const auto add_overflow = [&checksum] {
    while (checksum & 0xff'ff'00'00) {
      const std::uint16_t overflow = checksum >> 16;
      checksum &= 0xff'ff;
      checksum += overflow;
    }
  };

  for (unsigned i = 0; i < msg_array.size(); i += sizeof(std::uint16_t)) {
    std::uint16_t ui;
    std::memcpy(&ui, &msg_array[i], sizeof(std::uint16_t));
    checksum += ui;
    add_overflow();
  }

  for (unsigned i = 0; i < data.size(); i += sizeof(std::uint16_t)) {
    std::uint16_t ui;
    std::memcpy(&ui, &data[i], sizeof(std::uint16_t));
    checksum += ui;
    add_overflow();
  }
  checksum = util::ntohs(checksum);

  if (data.size() % 2 == 1) {
    const std::uint16_t ui = ((std::uint16_t)data.back()) << 8;
    checksum += ui;
    add_overflow();
  }

  return ~checksum;
}

inline message_type extract_message_type(std::span<const std::uint8_t> data) {
  assert(!data.empty());
  return (message_type)data[0];
}

struct echo_message_with_data {
  echo_message m_message;
  std::span<const std::uint8_t> m_data;
};

constexpr inline auto ntoh(const echo_message &msg) {
  auto copy = msg;
  copy.m_checksum = util::ntohs(copy.m_checksum);
  copy.m_identifier = util::ntohs(copy.m_identifier);
  copy.m_seq_number = util::ntohs(copy.m_seq_number);
  return copy;
}

inline std::expected<echo_message_with_data, message_reading_error>
read_echo_message_no_ntoh(std::span<const std::uint8_t> data) {
  if (data.size() < sizeof(echo_message)) {
    return std::unexpected{message_reading_error::no_enough_data};
  }

  echo_message msg;
  std::memcpy(&msg, data.data(), sizeof(msg));
  return echo_message_with_data{msg, data.subspan(sizeof(echo_message))};
}

inline std::expected<echo_message_with_data, message_reading_error>
read_echo_message(std::span<const std::uint8_t> data) {
  auto msg = read_echo_message_no_ntoh(data);
  if (!msg.has_value()) {
    return msg;
  }

  msg->m_message = ntoh(msg->m_message);
  return msg;
}

inline std::expected<echo_message_with_data, message_reading_error>
read_echo_reply_message(std::span<const std::uint8_t> data) {
  return read_echo_message(data);
}

} // namespace cool_protocols::icmp
