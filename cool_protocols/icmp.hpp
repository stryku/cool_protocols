#pragma once

#include "utils.hpp"

#include <atomic>
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

inline message_type extract_message_type(std::span<const std::uint8_t> data) {
  assert(!data.empty());
  return (message_type)data[0];
}

struct echo_message_with_data {
  echo_message m_message;
  std::span<const std::uint8_t> m_data;
};

inline std::expected<echo_message_with_data, message_reading_error>
read_echo_message(std::span<const std::uint8_t> data) {
  if (data.size() < sizeof(echo_message)) {
    return std::unexpected{message_reading_error::no_enough_data};
  }

  echo_message msg;
  std::memcpy(&msg, data.data(), sizeof(msg));

  msg.m_checksum = util::ntohs(msg.m_checksum);
  msg.m_identifier = util::ntohs(msg.m_identifier);
  msg.m_seq_number = util::ntohs(msg.m_seq_number);

  return echo_message_with_data{msg, data.subspan(sizeof(echo_message))};
}

inline std::expected<echo_message_with_data, message_reading_error>
read_echo_reply_message(std::span<const std::uint8_t> data) {
  return read_echo_message(data);
}

} // namespace cool_protocols::icmp
