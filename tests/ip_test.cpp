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

TEST_F(IpTest, ReadInternetHeader_BufferEmpty) {
  m_buffer.clear();
  const auto got_header = read_internet_header(m_buffer);
  ASSERT_FALSE(got_header.has_value());
  EXPECT_EQ(got_header.error(), internet_header_reading_error::no_enough_data);
}

TEST_F(IpTest, ReadInternetHeader_MalformedLength) {

  for (unsigned header_length = 0;
       header_length < k_min_valid_internet_header_length; ++header_length) {

    auto header = make_default_header();
    header.m_version_and_length.m_internet_header_length = header_length;
    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_FALSE(got_header.has_value());
    EXPECT_EQ(got_header.error(),
              internet_header_reading_error::malformed_length);
  }

  // No need to test > max because max == 0xf = 15, and 16+ doesn't fit in the
  // 4 bit field
}

TEST_F(IpTest, ReadInternetHeader_ValidHeaderLength) {
  for (unsigned header_length = k_min_valid_internet_header_length;
       header_length <= k_max_valid_internet_header_length; ++header_length) {

    auto header = make_default_header();
    header.m_version_and_length.m_internet_header_length = header_length;
    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());
    EXPECT_EQ(got_header.value(), header);
  }
}

TEST_F(IpTest, ReadInternetHeader_BufferTooSmallForHeader) {

  for (unsigned header_length = k_min_valid_internet_header_length;
       header_length <= k_max_valid_internet_header_length; ++header_length) {

    auto header = make_default_header();
    header.m_version_and_length.m_internet_header_length = header_length;
    write_header(header);

    // Make buffer too small
    m_buffer.resize(header_length - 1);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_FALSE(got_header.has_value());
    EXPECT_EQ(got_header.error(),
              internet_header_reading_error::no_enough_data);
  }
}

} // namespace cool_protocols::ip::test
