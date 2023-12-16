#pragma once

#include <fmt/format.h>

#include <string_view>
#include <vector>

#define OSTREAM_OP(TYPE)                                                       \
  inline std::ostream &operator<<(std::ostream &out, const TYPE &val) {        \
    return out << fmt::to_string(val);                                         \
  }

namespace cool_protocols {

inline void test_print(std::string_view str) {
  fmt::print("[          ] {}\n", str);
}

inline std::uint8_t hex_to_bin(char c) {
  constexpr char to_add[] = {0, 9};
  const bool is_alpha_char = (c & 0b01000000);
  return (c & 0x0f) + to_add[is_alpha_char];
}

inline std::vector<std::uint8_t> hex_str_to_bin(std::string_view hex) {

  std::vector<std::uint8_t> bin;

  for (unsigned i = 0; i < hex.size();) {

    if (std::isspace(hex[i])) {
      ++i;
      continue;
    }

    std::uint8_t byte = hex_to_bin(hex[i++]);
    byte <<= 4u;
    if (i < hex.size()) {
      byte |= hex_to_bin(hex[i++]);
    }

    bin.push_back(byte);
  }

  return bin;
}

} // namespace cool_protocols