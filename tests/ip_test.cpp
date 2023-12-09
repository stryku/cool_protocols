#include "cool_protocols/ip.hpp"
#include "cool_protocols/ip_fmt.hpp"

#include <fmt/format.h>

#include <atomic>
#include <gtest/gtest.h>

namespace cool_protocols::ip {

std::ostream &operator<<(std::ostream &out, const internet_header &header) {
  return out << fmt::to_string(header);
}

} // namespace cool_protocols::ip

namespace cool_protocols::ip::option {

std::ostream &operator<<(std::ostream &out, const option_type &ot) {
  return out << fmt::to_string(ot);
}

} // namespace cool_protocols::ip::option

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

TEST_F(IpTest, ReadInternetHeader_BasicRandomValues) {
  const internet_header header{
      .m_version_and_length = {.m_version = 0, .m_internet_header_length = 7},
      .m_type_of_service = {.m_precedence = 3,
                            .m_delay = 1,
                            .m_throughput = 1,
                            .m_reliability = 1,
                            .m_reserved = 3},
      .m_total_length = 4242,
      .m_identification = 5222,
      .m_protocol = 129,
      .m_header_checksum = 31233,
      .m_source_address = 0xaabbccdd,
      .m_destination_address = 0x00112233,
      .m_options = {1, 2, 3, 4, 5, 6, 7, 8}};

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());
  EXPECT_EQ(got_header.value(), header);
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

TEST_F(IpTest, OptionsReader_NoOptions) {
  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  ASSERT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_EndOfList) {
  // First octet of word
  {
    auto header = make_default_header();

    // Add option
    header.m_options[0] = option::k_end_of_list.to_uint8();
    header.m_version_and_length.m_internet_header_length += 1;

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};

    ASSERT_TRUE(reader.possibly_has_options());

    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
    EXPECT_TRUE(got_option.value().m_data.empty());
  }
  // First octet of word
  {
    auto header = make_default_header();

    // Add option
    header.m_options[0] = option::k_no_operation.to_uint8();
    header.m_options[1] = option::k_end_of_list.to_uint8();
    header.m_version_and_length.m_internet_header_length += 1;

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};

    // No-op
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      EXPECT_EQ(got_option.value().m_type, option::k_no_operation);
      EXPECT_TRUE(got_option.value().m_data.empty());
    }

    // End of list
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
      EXPECT_TRUE(got_option.value().m_data.empty());
    }
  }
  // Last octet of word
  {
    auto header = make_default_header();

    // Add option
    header.m_options[0] = option::k_no_operation.to_uint8();
    header.m_options[1] = option::k_no_operation.to_uint8();
    header.m_options[2] = option::k_no_operation.to_uint8();
    header.m_options[3] = option::k_end_of_list.to_uint8();
    header.m_version_and_length.m_internet_header_length += 1;

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};

    // No-op
    for (int i = 0; i < 3; ++i) {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      EXPECT_EQ(got_option.value().m_type, option::k_no_operation);
      EXPECT_TRUE(got_option.value().m_data.empty());
    }

    // End of list
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
      EXPECT_TRUE(got_option.value().m_data.empty());
    }
  }
}

TEST_F(IpTest, OptionsReader_OptionsEndExactlyAtHeaderEnd_NoEndOfListOption) {

  auto header = make_default_header();

  // Add option
  header.m_options[0] = option::k_no_operation.to_uint8();
  header.m_options[1] = option::k_no_operation.to_uint8();
  header.m_options[2] = option::k_no_operation.to_uint8();
  header.m_options[3] = option::k_no_operation.to_uint8();
  header.m_version_and_length.m_internet_header_length += 1;

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};

  // No-op
  for (int i = 0; i < 4; ++i) {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    EXPECT_EQ(got_option.value().m_type, option::k_no_operation);
    EXPECT_TRUE(got_option.value().m_data.empty());
  }

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_Security) {

  auto header = make_default_header();

  // Add option
  header.m_options[0] = option::k_security.to_uint8();
  header.m_options[1] = 11; // Length
  // Data
  header.m_options[2] = 'S';
  header.m_options[3] = 'S';
  header.m_options[4] = 'C';
  header.m_options[5] = 'C';
  header.m_options[6] = 'H';
  header.m_options[7] = 'H';
  header.m_options[8] = 'T';
  header.m_options[9] = 'T';
  header.m_options[10] = 'T';

  // End of list
  header.m_options[11] = option::k_end_of_list.to_uint8();

  header.m_version_and_length.m_internet_header_length += 3;

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    ASSERT_EQ(got_option.value().m_type, option::k_security);
    EXPECT_EQ(got_option.value().m_data.size(), 9);
    EXPECT_EQ(got_option.value().m_data[0], 'S');
    EXPECT_EQ(got_option.value().m_data[1], 'S');
    EXPECT_EQ(got_option.value().m_data[2], 'C');
    EXPECT_EQ(got_option.value().m_data[3], 'C');
    EXPECT_EQ(got_option.value().m_data[4], 'H');
    EXPECT_EQ(got_option.value().m_data[5], 'H');
    EXPECT_EQ(got_option.value().m_data[6], 'T');
    EXPECT_EQ(got_option.value().m_data[7], 'T');
    EXPECT_EQ(got_option.value().m_data[8], 'T');
  }
  {
    EXPECT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
    EXPECT_TRUE(got_option.value().m_data.empty());
  }

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_SecurityEndsExactlyAtEndOfHeader) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_end_of_list.to_uint8();

  // Add option
  header.m_options[1] = option::k_security.to_uint8();
  header.m_options[2] = 11; // Length
  // Data
  header.m_options[3] = 'S';
  header.m_options[4] = 'S';
  header.m_options[5] = 'C';
  header.m_options[6] = 'C';
  header.m_options[7] = 'H';
  header.m_options[8] = 'H';
  header.m_options[9] = 'T';
  header.m_options[10] = 'T';
  header.m_options[11] = 'T';

  header.m_version_and_length.m_internet_header_length += 3;

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    EXPECT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
    EXPECT_TRUE(got_option.value().m_data.empty());
  }
  {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    ASSERT_EQ(got_option.value().m_type, option::k_security);
    EXPECT_EQ(got_option.value().m_data.size(), 9);
    EXPECT_EQ(got_option.value().m_data[0], 'S');
    EXPECT_EQ(got_option.value().m_data[1], 'S');
    EXPECT_EQ(got_option.value().m_data[2], 'C');
    EXPECT_EQ(got_option.value().m_data[3], 'C');
    EXPECT_EQ(got_option.value().m_data[4], 'H');
    EXPECT_EQ(got_option.value().m_data[5], 'H');
    EXPECT_EQ(got_option.value().m_data[6], 'T');
    EXPECT_EQ(got_option.value().m_data[7], 'T');
    EXPECT_EQ(got_option.value().m_data[8], 'T');
  }
  EXPECT_FALSE(reader.possibly_has_options());
}

} // namespace cool_protocols::ip::test
