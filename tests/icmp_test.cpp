#include "cool_protocols/formatters.hpp"
#include "cool_protocols/icmp.hpp"
#include "cool_protocols/ip.hpp"

#include "utils.hpp"

#include <fmt/format.h>

#include <atomic>
#include <gtest/gtest.h>

namespace cool_protocols::icmp {

OSTREAM_OP(echo_message)
OSTREAM_OP(message_reading_error)
OSTREAM_OP(message_type)

} // namespace cool_protocols::icmp

namespace cool_protocols::icmp::test {

using namespace std::literals;

class IcmpTest : public ::testing::Test {
public:
  void setup(std::size_t buffer_size) {
    m_buffer.resize(buffer_size);
  }

  void SetUp() override {
    setup(1024);
  }

  template <typename T> void write_header(const T &header) {
    std::memcpy(m_buffer.data(), &header, sizeof(header));
  }

  std::vector<std::uint8_t> m_buffer;
};

TEST_F(IcmpTest, Echo_Sizeof) {
  EXPECT_EQ(sizeof(echo_message), 8);
}

TEST_F(IcmpTest, Echo_Endianess) {

  // clang-format off
  const std::array<std::uint8_t, sizeof(echo_message) + 4>
      binary_header{
        0x15, 0x23, 0x34, 0x45,
        0x56, 0x67, 0x78, 0x89,
        0x90, 0x0a, 0xab, 0xbc
      };
  // clang-format on

  const auto header = read_echo_message(binary_header);
  ASSERT_TRUE(header.has_value());

  EXPECT_EQ(header->m_message.m_type, 0x15);
  EXPECT_EQ(header->m_message.m_code, 0x23);
  EXPECT_EQ(header->m_message.m_checksum, 0x3445);
  EXPECT_EQ(header->m_message.m_identifier, 0x5667);
  EXPECT_EQ(header->m_message.m_seq_number, 0x7889);

  EXPECT_EQ(header->m_data.size(), 4);
}

TEST_F(IcmpTest, EchoReply_Endianess) {

  // clang-format off
  const std::array<std::uint8_t, sizeof(echo_message) + 4>
      binary_header{
        0x15, 0x23, 0x34, 0x45,
        0x56, 0x67, 0x78, 0x89,
        0x90, 0x0a, 0xab, 0xbc
      };
  // clang-format on

  const auto header = read_echo_reply_message(binary_header);
  ASSERT_TRUE(header.has_value());

  EXPECT_EQ(header->m_message.m_type, 0x15);
  EXPECT_EQ(header->m_message.m_code, 0x23);
  EXPECT_EQ(header->m_message.m_checksum, 0x3445);
  EXPECT_EQ(header->m_message.m_identifier, 0x5667);
  EXPECT_EQ(header->m_message.m_seq_number, 0x7889);

  EXPECT_EQ(header->m_data.size(), 4);
}

TEST_F(IcmpTest, ChecksumCalculation) {
  // const auto hex =
  //     "080000000001000207CD7D6500000000208E040000000000101112131415161718191A1B"
  //     "1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637";

  // const auto hex =
  //     "080000000001000106cd7d6500000000a528040000000000101112131415161718191a1b"
  //     "1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";

  std::array<std::uint8_t, 64> bin{
      0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x06, 0xcd, 0x7d,
      0x65, 0x00, 0x00, 0x00, 0x00, 0xa5, 0x28, 0x04, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
      0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
      0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

  // const std::vector<std::uint8_t> bin = hex_str_to_bin(hex);

  // EXPECT_EQ(calc_checksum(bin), 0x8f69);
  EXPECT_EQ(calc_checksum(bin), 0x0bd0);
}

} // namespace cool_protocols::icmp::test
