#pragma once

#include <bit>
#include <cstdint>

namespace cool_protocols::util {

namespace detail {
inline constexpr std::uint32_t swap(std::uint32_t hostlong) {
  return (hostlong << 24) | ((hostlong & 0xff'00) << 8) |
         ((hostlong & 0xff'00'00) >> 8) | (hostlong >> 24);
}

inline constexpr std::uint16_t swap(std::uint16_t hostshort) {
  return (hostshort << 8) | (hostshort >> 8);
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

} // namespace cool_protocols::util
