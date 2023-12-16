#pragma once

#include <fmt/format.h>

inline void test_print(std::string_view str) {
  fmt::print("[          ] {}\n", str);
}

#define OSTREAM_OP(TYPE)                                                       \
  inline std::ostream &operator<<(std::ostream &out, const TYPE &val) {        \
    return out << fmt::to_string(val);                                         \
  }
