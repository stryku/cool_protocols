#pragma once

#include <cstdint>

namespace cool_protocols::ip {

struct internet_header {
  std::uint8_t m_version : 4 = 0;
  std::uint8_t m_internet_header_length : 4 = 0;
  std::uint8_t m_type_of_service = 0;
  std::uint16_t m_total_length = 0;

  std::uint16_t m_identification = 0;
  std::uint8_t m_flags : 3 = 0;
  std::uint16_t m_fragment_offset : 13 = 0;

  std::uint8_t m_time_to_live = 0;
  std::uint8_t m_protocol = 0;
  std::uint16_t m_header_checksum = 0;
  std::uint32_t m_source_address = 0;
  std::uint32_t m_destination_address = 0;
  std::uint8_t m_options[40];
} __attribute__((packed));

static_assert(sizeof(internet_header) == 60);

} // namespace cool_protocols::ip
