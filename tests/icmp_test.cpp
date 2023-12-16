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

} // namespace cool_protocols::icmp::test
