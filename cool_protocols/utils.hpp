#pragma once

#include <bit>
#include <cassert>
#include <cctype>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace cool_protocols::util {

namespace detail {
inline constexpr std::uint32_t swap(std::uint32_t hostlong) {
  return (hostlong << 24) | ((hostlong & 0xff'00) << 8) |
         ((hostlong & 0xff'00'00) >> 8) | (hostlong >> 24);
}

inline constexpr std::uint16_t swap(std::uint16_t hostshort) {
  return (hostshort << 8) | (hostshort >> 8);
}

template <typename T>
inline std::span<const std::uint8_t> as_bytes(const T &value) {
  const auto bytes = std::as_bytes(std::span(&value, 1));
  return std::span((const std::uint8_t *)bytes.data(), bytes.size());
}

} // namespace detail

inline constexpr std::uint32_t htonl(std::uint32_t hostlong) {
  if constexpr (std::endian::native == std::endian::big) {
    return hostlong;
  } else {
    return detail::swap(hostlong);
  }
}

inline constexpr std::uint16_t htons(std::uint16_t hostshort) {
  if constexpr (std::endian::native == std::endian::big) {
    return hostshort;
  } else {
    return detail::swap(hostshort);
  }
}

inline constexpr std::uint32_t ntohl(std::uint32_t netlong) {
  if constexpr (std::endian::native == std::endian::big) {
    return netlong;
  } else {
    return detail::swap(netlong);
  }
}

inline constexpr std::uint16_t ntohs(std::uint16_t netshort) {
  if constexpr (std::endian::native == std::endian::big) {
    return netshort;
  } else {
    return detail::swap(netshort);
  }
}

#pragma pack(1)
template <typename T, typename Tag> struct strong_type_packed {

  T *operator->() {
    return &m_value;
  }

  const T *operator->() const {
    return &m_value;
  }

  T m_value{};
};
#pragma pack()

template <typename T>
concept span_like = std::same_as<T, std::span<std::uint8_t>> ||
                    std::same_as<T, std::span<const std::uint8_t>> ||
                    std::convertible_to<T, std::span<const std::uint8_t>>;

template <span_like... Args>
std::span<const std::uint8_t> write_to_buffer(std::span<std::uint8_t> buffer,
                                              const Args... args) {

  std::size_t pos = 0;
  const auto write = [&pos, &buffer](const auto &arg) {
    std::memcpy(buffer.data() + pos, arg.data(), arg.size());
    pos += arg.size();
  };

  (write(args), ...);

  return std::span(buffer.data(), pos);
}

constexpr inline std::uint32_t inet_addr(std::string_view str_addr) {

  std::uint32_t addr = 0;

  std::uint8_t part = 0;

  for (char c : str_addr) {

    if (std::isdigit(c)) {
      part *= 10;
      part += (c - '0');
    } else {
      assert(c == '.');
      addr <<= 8;
      addr += part;
      part = 0;
    }
  }

  addr <<= 8;
  addr += part;

  return addr;
}

namespace detail {

class checksum_calculator {
public:
  void add(std::uint16_t value) {
    m_checksum += value;
    while (m_checksum & 0xff'ff'00'00) {
      const std::uint16_t overflow = m_checksum >> 16;
      m_checksum &= 0xff'ff;
      m_checksum += overflow;
    }
  }

  void add(std::uint8_t high, std::uint8_t low) {
    const std::uint16_t ui16 = ((std::uint16_t)high << 8) | (std::uint16_t)low;
    add(ui16);
  }

  void add(std::uint32_t value) {
    add((std::uint16_t)((value & 0xff'ff'00'00) >> 16));
    add((std::uint16_t)(value & 0x00'00'ff'ff));
  }

  void add(std::span<const std::uint8_t> data) {
    for (unsigned i = 0; i < data.size(); i += sizeof(std::uint16_t)) {
      std::uint16_t ui;
      std::memcpy(&ui, &data[i], sizeof(std::uint16_t));
      add(ui);
    }

    if (data.size() % 2 == 1) {
      const std::uint16_t ui = ((std::uint16_t)data.back()) << 8;
      add(ui);
    }
  }

  std::uint16_t finalize() {
    return ~m_checksum;
  }

protected:
  std::uint32_t m_checksum = 0;

private:
  void add_overflow() {
    while (m_checksum & 0xff'ff'00'00) {
      const std::uint16_t overflow = m_checksum >> 16;
      m_checksum &= 0xff'ff;
      m_checksum += overflow;
    }
  };
};

} // namespace detail

// using host_order_checksum_t =
//     strong_type_packed<std::uint16_t, struct _tag_host_order_checksum>;
// using network_order_checksum_t =
//     strong_type_packed<std::uint16_t, struct _tag_network_order_checksum>;

// class host_checksum_calculator
//     : public detail::checksum_calculator<host_checksum_calculator> {
// public:
//   using checksum_t = host_order_checksum_t;

// private:
//   friend detail::checksum_calculator<host_checksum_calculator>;
//   checksum_t finalize_impl() {}
// };

} // namespace cool_protocols::util
