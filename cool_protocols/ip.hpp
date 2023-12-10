#pragma once

#include <__expected/unexpect.h>
#include <fmt/format.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <stdexcept>

namespace cool_protocols::ip {

namespace option {

enum class copied : std::uint8_t { not_copied = 0, copied = 1 };

enum class classes : std::uint8_t {
  control = 0,
  reserved = 1,
  debugging_and_measurement = 2,
  reserved2 = 3
};

enum class number : std::uint8_t {
  end_of_list = 0,
  no_operation = 1,
  security = 2,
  loose_source_routing = 3,
  internet_timestamp = 4,
  record_route = 7,
  stream_id = 8,
  strict_source_routing = 9
};

struct option_type {
  constexpr option_type() = default;
  explicit option_type(std::uint8_t value) {
    std::memcpy(this, &value, sizeof(option_type));
  }

  constexpr option_type(copied copied_, classes class_, number number_)
      : m_number{(std::uint8_t)number_}, m_class{(std::uint8_t)class_},
        m_copied{(std::uint8_t)copied_} {}

  std::uint8_t m_number : 5 = 0;
  std::uint8_t m_class : 2 = 0;
  std::uint8_t m_copied : 1 = 0;

  constexpr bool operator==(const option_type &) const = default;

  constexpr std::uint8_t to_uint8() const {
    return (m_copied << 7u) + (m_class << 5) + m_number;
  }

} __attribute__((packed));

static_assert(sizeof(option_type) == 1);

namespace detail {

inline constexpr bool can_memcpy_option_type() {
  option_type type;
  type.m_copied = 1;
  type.m_class = 1;
  type.m_number = 8;

  const std::uint8_t expected = 0b10101000;
  return std::bit_cast<std::uint8_t>(type) == expected;
};

} // namespace detail

constexpr option_type k_end_of_list{};
constexpr option_type k_no_operation{copied::not_copied, classes::control,
                                     number::no_operation};
constexpr option_type k_security{copied::copied, classes::control,
                                 number::security};
constexpr option_type k_loose_source_routing{copied::copied, classes::control,
                                             number::loose_source_routing};
constexpr option_type k_internet_timestamp{copied::not_copied,
                                           classes::debugging_and_measurement,
                                           number::internet_timestamp};
constexpr option_type k_record_route{copied::not_copied, classes::control,
                                     number::record_route};
constexpr option_type k_stream_id{copied::copied, classes::control,
                                  number::stream_id};
constexpr option_type k_strict_source_routing{copied::copied, classes::control,
                                              number::strict_source_routing};

constexpr std::uint8_t k_security_length = 11;
constexpr std::uint8_t k_stream_id_length = 4;
constexpr std::uint8_t k_min_internet_timestamp_length = 4;
constexpr std::uint8_t k_min_internet_timestamp_pointer = 5;
constexpr std::uint8_t k_min_source_routing_length = 3;
constexpr std::uint8_t k_min_source_routing_pointer = 4;

} // namespace option

constexpr std::size_t k_internet_header_length_without_options = 5 * 4;
constexpr std::size_t k_min_valid_internet_header_length = 5;
constexpr std::size_t k_max_valid_internet_header_length = (1 << 4) - 1u;

namespace type_of_service {

constexpr std::uint8_t k_normal_delay = 0;
constexpr std::uint8_t k_low_delay = 1;
constexpr std::uint8_t k_normal_throughput = 0;
constexpr std::uint8_t k_high_throughput = 1;
constexpr std::uint8_t k_normal_reliability = 0;
constexpr std::uint8_t k_high_reliability = 1;

constexpr std::uint8_t k_network_control = 0b111;
constexpr std::uint8_t k_internetwork_control = 0b110;
constexpr std::uint8_t k_critic_ecp = 0b101;
constexpr std::uint8_t k_flash_override = 0b100;
constexpr std::uint8_t k_flash = 0b011;
constexpr std::uint8_t k_immediate = 0b010;
constexpr std::uint8_t k_priority = 0b001;
constexpr std::uint8_t k_routine = 0b000;

} // namespace type_of_service

namespace flags {

constexpr std::uint8_t k_may_fragment = 0;
constexpr std::uint8_t k_dont_fragment = 1;
constexpr std::uint8_t k_last_fragment = 0;
constexpr std::uint8_t k_more_fragments = 1;

} // namespace flags

struct internet_header {

  struct version_and_length {
    std::uint8_t m_version : 4 = 0;
    std::uint8_t m_internet_header_length : 4 = 0;
    constexpr bool operator==(const version_and_length &) const = default;
  } __attribute__((packed)) m_version_and_length;

  struct type_of_service {
    std::uint8_t m_precedence : 3 = 0;
    std::uint8_t m_delay : 1 = 0;
    std::uint8_t m_throughput : 1 = 0;
    std::uint8_t m_reliability : 1 = 0;
    std::uint8_t m_reserved : 2 = 0;
    constexpr bool operator==(const type_of_service &) const = default;

  } __attribute__((packed)) m_type_of_service;

  std::uint16_t m_total_length = 0;

  std::uint16_t m_identification = 0;
  std::uint8_t m_flags : 3 = 0;
  std::uint16_t m_fragment_offset : 13 = 0;

  std::uint8_t m_time_to_live = 0;
  std::uint8_t m_protocol = 0;
  std::uint16_t m_header_checksum = 0;
  std::uint32_t m_source_address = 0;
  std::uint32_t m_destination_address = 0;
  std::uint8_t m_options[40]{};

  constexpr bool operator==(const internet_header &) const = default;

} __attribute__((packed));

static_assert(sizeof(internet_header) == 60);

enum class internet_header_reading_error { no_enough_data, malformed_length };

inline std::expected<internet_header, internet_header_reading_error>
read_internet_header(std::span<const std::byte> buffer) {
  if (buffer.size() < sizeof(internet_header::version_and_length)) {
    return std::unexpected{internet_header_reading_error::no_enough_data};
  }

  const auto version_and_length =
      *reinterpret_cast<const internet_header::version_and_length *>(
          buffer.data());

  if (version_and_length.m_internet_header_length <
          k_min_valid_internet_header_length ||
      version_and_length.m_internet_header_length >
          k_max_valid_internet_header_length) {
    return std::unexpected{internet_header_reading_error::malformed_length};
  }

  if (buffer.size() < version_and_length.m_internet_header_length) {
    return std::unexpected{internet_header_reading_error::no_enough_data};
  }

  internet_header header;
  if (option::detail::can_memcpy_option_type()) {
    std::memcpy(&header, buffer.data(),
                version_and_length.m_internet_header_length * 4);
  } else {
    // TODO implement
    throw std::runtime_error("Not implemented");
  }

  return header;
}

struct read_option {
  option::option_type m_type;
  std::span<const std::uint8_t> m_data{};
};

// TODO rename to decoded_routing_option
struct read_source_routing_option {
  std::uint8_t m_pointer = 0;
  std::span<const std::uint8_t> m_data{};
};

enum class internet_overflow_flag : std::uint8_t {
  timestamp_only = 0,
  timestamp_preceded_with_address = 1,
  address_is_prespecified = 3
};

struct internet_timestamp_overflow_flags {
  std::uint8_t m_value = 0;

  std::uint8_t get_overflow() const {
    return (m_value & 0xf0) >> 4u;
  }

  void set_overflow(std::uint8_t value) {
    m_value |= (value << 4u);
  }

  internet_overflow_flag get_flags() const {
    return (internet_overflow_flag)(m_value & 0xf);
  }

  void set_flags(internet_overflow_flag value) {
    m_value |= (std::uint8_t)value;
  }
};

struct decoded_internet_timestamp_option {
  std::uint8_t m_pointer = 0;
  internet_timestamp_overflow_flags m_overflow_and_flags;
  std::span<const std::uint8_t> m_data;
};

enum class security_level : std::uint16_t {
  unclassified = 0,
  confidential = 0b11110001'00110101,
  efto = 0b01111000'10011010,
  mmmm = 0b10111100'01001101,
  prog = 0b01011110'00100110,
  restricted = 0b10101111'00010011,
  secret = 0b11010111'10001000,
  top_secret = 0b01101011'11000101,
  reserved1 = 0b00110101'11100010,
  reserved2 = 0b10011010'11110001,
  reserved3 = 0b01001101'01111000,
  reserved4 = 0b00100100'10111101,
  reserved5 = 0b00010011'01011110,
  reserved6 = 0b10001001'10101111,
  reserved7 = 0b11100010'01101011
};

struct decoded_security_option {
  security_level m_security_level = security_level::unclassified;
  std::uint16_t m_compartments = 0;
  std::uint16_t m_handling_restrictions = 0;
  std::uint32_t m_transmission_control_code : 24 = 0;
};

enum class option_reading_error {
  no_more_data,
  no_enough_data,
  malformed_security_length,
  malformed_stream_id_length,
  malformed_internet_timestamp_length,
  malformed_pointer_value
};

class options_reader {
public:
  options_reader(const internet_header &header) {
    const auto option_bytes =
        header.m_version_and_length.m_internet_header_length * 4u -
        k_internet_header_length_without_options;

    if (option_bytes > 0) {
      m_options_buffer =
          std::span<const std::uint8_t>(&header.m_options[0], option_bytes);
    }
  }

  constexpr bool possibly_has_options() const {
    return !m_options_buffer.empty();
  }

  std::expected<read_option, option_reading_error> try_read_next() {
    assert(possibly_has_options());

    const option::option_type type(eat());

    if (type == option::k_end_of_list || type == option::k_no_operation) {
      return read_option{type};
    }

    if (type == option::k_security) {
      return try_read_security();
    }

    if (type == option::k_loose_source_routing) {
      return try_read_routing(option::k_loose_source_routing);
    }

    if (type == option::k_strict_source_routing) {
      return try_read_routing(option::k_strict_source_routing);
    }

    if (type == option::k_record_route) {
      return try_read_routing(option::k_record_route);
    }

    if (type == option::k_stream_id) {
      return try_read_stream_id();
    }

    if (type == option::k_internet_timestamp) {
      return try_read_internet_timestamp();
    }

    return {};
  }

  static std::expected<read_source_routing_option, option_reading_error>
  decode_routing(std::span<const std::uint8_t> data) {

    read_source_routing_option read;
    read.m_pointer = *data.begin();

    if (read.m_pointer < option::k_min_source_routing_pointer) [[unlikely]] {
      return std::unexpected{option_reading_error::malformed_pointer_value};
    }

    read.m_data = data.subspan(1);
    return read;
  }

  static std::expected<decoded_internet_timestamp_option, option_reading_error>
  decode_internet_timestamp(std::span<const std::uint8_t> data) {

    decoded_internet_timestamp_option decoded;
    decoded.m_pointer = *data.begin();

    if (decoded.m_pointer < option::k_min_internet_timestamp_pointer) {
      return std::unexpected{option_reading_error::malformed_pointer_value};
    }

    data = data.subspan(1);
    decoded.m_overflow_and_flags =
        internet_timestamp_overflow_flags{*data.begin()};

    decoded.m_data = data.subspan(1);

    return decoded;
  }

  static std::expected<decoded_security_option, option_reading_error>
  decode_security(std::span<const std::uint8_t> data) {

    //-2 because not option type and length
    assert(data.size() == option::k_security_length - 2);

    decoded_security_option decoded;

    const auto eat16 = [&] {
      const std::uint16_t ret =
          ((std::uint16_t)data[0] << 8u) | ((std::uint16_t)data[1]);
      data = data.subspan(2);
      return ret;
    };

    decoded.m_security_level = (security_level)eat16();
    decoded.m_compartments = eat16();
    decoded.m_handling_restrictions = eat16();

    decoded.m_transmission_control_code = ((std::uint32_t)data[0] << 16u) |
                                          ((std::uint32_t)data[1] << 8u) |
                                          ((std::uint32_t)data[2]);

    return decoded;
  }

private:
  std::expected<read_option, option_reading_error> try_read_security() {
    if (!can_eat()) {
      // Can't eat length
      return clear_and_error(option_reading_error::no_enough_data);
    }

    const std::uint8_t length = eat();

    if (length != option::k_security_length) [[unlikely]] {

      if (length < 2) {
        // Can't eat more. Just return.
        return std::unexpected{option_reading_error::malformed_security_length};
      }

      // Omit option type and length.
      const std::uint8_t data_length = length - 2;

      if (!can_eat(data_length)) {
        return clear_and_error(option_reading_error::malformed_security_length);
      }

      // Don't clear. Can try to omit the `length` bytes and read the next
      // option
      eat(data_length);
      return std::unexpected{option_reading_error::malformed_security_length};
    }

    //-2 because option type and length already eaten.
    if (!can_eat(length - 2)) {
      return clear_and_error(option_reading_error::no_enough_data);
    }

    read_option read{option::k_security};
    // -2 because option type and length already eaten.
    read.m_data = eat(option::k_security_length - 2);
    return read;
  }

  std::expected<read_option, option_reading_error>
  try_read_routing(option::option_type type) {
    // only length because option type already eaten.
    if (!can_eat()) {
      // Can't eat length
      return clear_and_error(option_reading_error::no_enough_data);
    }

    const std::uint8_t length = eat();

    // -2 because option type, length already eaten
    if (!can_eat(length - 2)) {
      return clear_and_error(option_reading_error::no_enough_data);
    }

    read_option read{type};
    read.m_data = eat(length - 2);
    return read;
  }

  std::expected<read_option, option_reading_error> try_read_stream_id() {
    // only length because option type already eaten.
    if (!can_eat()) {
      // Can't eat length
      return clear_and_error(option_reading_error::no_enough_data);
    }

    const std::uint8_t length = eat();

    if (length != option::k_stream_id_length) [[unlikely]] {
      if (length < 2) {
        // Can't eat more. Just return.
        return std::unexpected{
            option_reading_error::malformed_stream_id_length};
      }

      // Omit option type and length.
      const std::uint8_t data_length = length - 2;

      if (!can_eat(data_length)) {
        return clear_and_error(
            option_reading_error::malformed_stream_id_length);
      }

      // Don't clear. Can try to omit the `length` bytes and read the next
      // option
      eat(data_length);
      return std::unexpected{option_reading_error::malformed_stream_id_length};
    }

    // -2 because option type, length already eaten
    if (!can_eat(length - 2)) {
      return clear_and_error(option_reading_error::no_enough_data);
    }

    read_option read{option::k_stream_id};
    read.m_data = eat(length - 2);
    return read;
  }

  std::expected<read_option, option_reading_error>
  try_read_internet_timestamp() {
    // only length because option type already eaten.
    if (!can_eat()) {
      // Can't eat length
      return clear_and_error(option_reading_error::no_enough_data);
    }

    const std::uint8_t length = eat();

    if (length < option::k_min_internet_timestamp_length) [[unlikely]] {
      if (length < 2) {
        // Can't eat more. Just return.
        return std::unexpected{
            option_reading_error::malformed_internet_timestamp_length};
      }

      // Omit option type and length.
      const std::uint8_t data_length = length - 2;

      if (!can_eat(data_length)) {
        return clear_and_error(
            option_reading_error::malformed_internet_timestamp_length);
      }

      // Don't clear. Can try to omit the `length` bytes and read the next
      // option
      eat(data_length);
      return std::unexpected{
          option_reading_error::malformed_internet_timestamp_length};
    }

    // -2 because option type, length already eaten
    if (!can_eat(length - 2)) {
      return clear_and_error(option_reading_error::no_enough_data);
    }

    read_option read{option::k_internet_timestamp};
    read.m_data = eat(length - 2);
    return read;
  }

  std::uint8_t eat() {
    assert(can_eat());
    const auto value = *m_options_buffer.begin();
    m_options_buffer = m_options_buffer.subspan(1);
    return value;
  }

  bool can_eat(unsigned n = 1) const {
    return m_options_buffer.size() >= n;
  }

  std::span<const std::uint8_t> eat(unsigned n) {
    assert(can_eat(n));
    const auto data = m_options_buffer.subspan(0, n);
    m_options_buffer = m_options_buffer.subspan(n);
    return data;
  }

  std::expected<read_option, option_reading_error>
  clear_and_error(option_reading_error err) {
    m_options_buffer = {};
    return std::unexpected{err};
  }

  std::span<const std::uint8_t> m_options_buffer;
};

} // namespace cool_protocols::ip
