#include "cool_protocols/ip.hpp"

#include <fmt/format.h>

#include <atomic>
#include <gtest/gtest.h>

namespace cool_protocols::ip {

std::ostream &operator<<(std::ostream &out, const internet_header &header) {
  return out << fmt::to_string(header);
}

} // namespace cool_protocols::ip

namespace cool_protocols::ip::test {

using namespace std::literals;

class IpTest : public ::testing::Test {
public:
  void setup(std::size_t buffer_size) {
    m_buffer.resize(buffer_size);

    const auto header = make_default_header();
    std::memcpy(m_buffer.data(), &header, sizeof(header));
  }

  void SetUp() override {
    setup(1024);
  }

  constexpr internet_header make_default_header() const {
    internet_header header;
    header.m_version_and_length.m_version = 4;
    header.m_version_and_length.m_internet_header_length =
        (std::uint8_t)k_min_valid_internet_header_length;

    return header;
  }

  void write_header(const internet_header &header) {
    std::memcpy(m_buffer.data(), &header, sizeof(header));
  }

  std::vector<std::byte> m_buffer;
};

TEST_F(IpTest, Sizeof) {
  EXPECT_EQ(sizeof(internet_header), 60);
}

TEST_F(IpTest, ReadInternetHeader_Basic) {
  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());
  EXPECT_EQ(got_header.value(), make_default_header());
}

} // namespace cool_protocols::ip::test
