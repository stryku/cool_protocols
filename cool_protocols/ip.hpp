#pragma once

#include <fmt/format.h>

#include <cstdint>
#include <cstring>
#include <expected>
#include <span>

namespace cool_protocols::ip {

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
  constexpr option_type(copied copied_, classes class_, number number_)
      : m_copied{(std::uint8_t)copied_}, m_class{(std::uint8_t)class_},
        m_number{(std::uint8_t)number_} {}

  std::uint8_t m_copied : 1 = 0;
  std::uint8_t m_class : 2 = 0;
  std::uint8_t m_number : 5 = 0;

  constexpr bool operator==(const option_type &) const = default;

  constexpr std::uint8_t to_uint8() const {
    return (m_copied << 7u) + (m_class << 5) + m_number;
  }

} __attribute__((packed));

static_assert(sizeof(option_type) == 1);

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
  std::memcpy(&header, buffer.data(),
              version_and_length.m_internet_header_length);

  return header;
}

} // namespace cool_protocols::ip

template <> struct fmt::formatter<cool_protocols::ip::internet_header> {

  constexpr auto parse(auto &ctx) const {
    return ctx.begin();
  }

  constexpr auto format(const cool_protocols::ip::internet_header &h,
                        auto &ctx) {
    return format_to(
        ctx.out(),
        "version={}, header-length={}, tos-precedence={}, tos-delay={}, "
        "tos-throughput={}, tos-reliability={}, tos-reserved={}, "
        "total-length={}, identification={}, flags={:#x}, fragment-offset={}, "
        "ttl={}, protocol={}, checksum={}, src-address={:#x}, "
        "dest-address={:#x}",
        h.m_version_and_length.m_version,
        h.m_version_and_length.m_internet_header_length,
        h.m_type_of_service.m_precedence, h.m_type_of_service.m_delay,
        h.m_type_of_service.m_throughput, h.m_type_of_service.m_reliability,
        h.m_type_of_service.m_reserved, h.m_total_length, h.m_identification,
        h.m_flags, h.m_fragment_offset, h.m_time_to_live, h.m_protocol,
        h.m_header_checksum, h.m_source_address, h.m_destination_address);
  }
};
