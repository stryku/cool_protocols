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

  const auto network_header = read_echo_message(binary_header);
  ASSERT_TRUE(network_header.has_value());

  EXPECT_EQ(network_header->m_data.size(), 4);

  const host_order_echo_message host_header = ntoh(network_header->m_message);

  EXPECT_EQ(host_header->m_type, 0x15);
  EXPECT_EQ(host_header->m_code, 0x23);
  EXPECT_EQ(host_header->m_checksum, 0x3445);
  EXPECT_EQ(host_header->m_identifier, 0x5667);
  EXPECT_EQ(host_header->m_seq_number, 0x7889);
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

  const auto network_header = read_echo_reply_message(binary_header);
  ASSERT_TRUE(network_header.has_value());

  EXPECT_EQ(network_header->m_data.size(), 4);

  const host_order_echo_reply_message host_header =
      ntoh(network_header->m_message);

  EXPECT_EQ(host_header->m_type, 0x15);
  EXPECT_EQ(host_header->m_code, 0x23);
  EXPECT_EQ(host_header->m_checksum, 0x3445);
  EXPECT_EQ(host_header->m_identifier, 0x5667);
  EXPECT_EQ(host_header->m_seq_number, 0x7889);
}

TEST_F(IcmpTest, ChecksumCalculation) {
  EXPECT_EQ(
      calc_checksum(hex_str_to_bin(
          "080000000001000207CD7D6500000000208E04000000000010111213141516171819"
          "1A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637")),
      0x8f69);
  EXPECT_EQ(calc_checksum(hex_str_to_bin(
                "080000000001000106cd7d6500000000a52804000000000010111213141516"
                "1718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435"
                "3637")),
            0x0bd0);
  EXPECT_EQ(
      calc_checksum(hex_str_to_bin(
          "000000000001000106cd7d6500000000a52804000000000010111213141516171819"
          "1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")),
      0x13d0);
  EXPECT_EQ(
      calc_checksum(hex_str_to_bin(
          "000000000001000207cd7d6500000000208e04000000000010111213141516171819"
          "1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")),
      0x9769);

  {
    const auto bin = hex_str_to_bin(
        "08000bd00001000106cd7d6500000000a528040000000000101112131415161718191a"
        "1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    auto msg = read_echo_message(bin);
    ASSERT_TRUE(msg.has_value());
    const auto checksum = util::ntohs(msg->m_message->m_checksum);
    msg->m_message->m_checksum = 0;
    const auto got_checksum = calc_checksum(msg->m_message, msg->m_data);
    EXPECT_EQ(checksum, got_checksum);
  }
  {
    const auto bin = hex_str_to_bin(
        "000013d00001000106cd7d6500000000a528040000000000101112131415161718191a"
        "1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    auto msg = read_echo_message(bin);
    ASSERT_TRUE(msg.has_value());
    const auto checksum = util::ntohs(msg->m_message->m_checksum);
    msg->m_message->m_checksum = 0;
    const auto got_checksum = calc_checksum(msg->m_message, msg->m_data);
    EXPECT_EQ(checksum, got_checksum);
  }
  {
    const auto bin = hex_str_to_bin(
        "08008f690001000207cd7d6500000000208e040000000000101112131415161718191a"
        "1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    auto msg = read_echo_message(bin);
    ASSERT_TRUE(msg.has_value());
    const auto checksum = util::ntohs(msg->m_message->m_checksum);
    msg->m_message->m_checksum = 0;
    const auto got_checksum = calc_checksum(msg->m_message, msg->m_data);
    EXPECT_EQ(checksum, got_checksum);
  }
  {
    const auto bin = hex_str_to_bin(
        "000097690001000207cd7d6500000000208e040000000000101112131415161718191a"
        "1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637");
    auto msg = read_echo_message(bin);
    ASSERT_TRUE(msg.has_value());
    const auto checksum = util::ntohs(msg->m_message->m_checksum);
    msg->m_message->m_checksum = 0;
    const auto got_checksum = calc_checksum(msg->m_message, msg->m_data);
    EXPECT_EQ(checksum, got_checksum);
  }
  {
    const auto bin = hex_str_to_bin("08007eb500010001aad2e399b40c0600");
    auto msg = read_echo_message(bin);
    ASSERT_TRUE(msg.has_value());
    msg->m_message->m_checksum = 0;
    const auto got_checksum = calc_checksum(msg->m_message, msg->m_data);
    EXPECT_EQ(got_checksum, 0xaf84);
  }
}

} // namespace cool_protocols::icmp::test
