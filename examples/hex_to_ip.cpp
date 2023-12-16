#include "cool_protocols/formatters.hpp"
#include "cool_protocols/ip.hpp"
#include "fmt/core.h"

#include <string_view>
#include <vector>

std::uint8_t hex_to_bin(char c) {
  constexpr char to_add[] = {0, 9};
  const bool is_alpha_char = (c & 0b01000000);
  return (c & 0x0f) + to_add[is_alpha_char];
}

std::vector<std::uint8_t> hex_str_to_bin(std::string_view hex) {

  std::vector<std::uint8_t> bin;

  for (unsigned i = 0; i < hex.size();) {

    if (std::isspace(hex[i])) {
      ++i;
      continue;
    }

    std::uint8_t byte = hex_to_bin(hex[i++]);
    byte <<= 4u;
    if (i + 1 < hex.size()) {
      byte |= hex_to_bin(hex[i++]);
    }

    bin.push_back(byte);
  }

  return bin;
}

int main(int argc, const char *argv[]) {

  std::string_view hex = "450000183db10000ff0180317f0000017f000001";

  if (argc == 2) {
    hex = argv[1];
    // fmt::print(R"(Usage: hext_to_ip "01 23 45 67 89 AB CD EF")");
    // return 1;
  }

  const std::vector<std::uint8_t> bin = hex_str_to_bin(hex);

  const auto header = cool_protocols::ip::read_internet_header(bin);

  if (!header.has_value()) {
    fmt::print("Error reading IP header: {}", header.error());
    return 1;
  }

  fmt::print("IP header: {}", header.value());
}
