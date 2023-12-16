#include "cool_protocols/ip.hpp"
#include "cool_protocols/ip_fmt.hpp"

#include <fmt/format.h>

#include <atomic>
#include <gtest/gtest.h>

void test_print(std::string_view str) {
  fmt::print("[          ] {}\n", str);
}

#define OSTREAM_OP(TYPE)                                                       \
  std::ostream &operator<<(std::ostream &out, const TYPE &val) {               \
    return out << fmt::to_string(val);                                         \
  }

namespace cool_protocols::ip {

OSTREAM_OP(internet_header)
OSTREAM_OP(option_reading_error)
OSTREAM_OP(internet_overflow_flag)

} // namespace cool_protocols::ip

namespace cool_protocols::ip::option {

OSTREAM_OP(option_type)

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
    header.m_version_and_length.set_version(4);
    header.m_version_and_length.set_internet_header_length(
        (std::uint8_t)k_min_valid_internet_header_length);

    return header;
  }

  void write_header(const internet_header &header) {
    std::memcpy(m_buffer.data(), &header, sizeof(header));
  }

  std::vector<std::uint8_t> m_buffer;
};

TEST_F(IpTest, Sizeof) {
  EXPECT_EQ(sizeof(internet_header), 60);
}

TEST_F(IpTest, Header_VersionAndLength) {
  internet_header header;

  EXPECT_EQ(header.m_version_and_length.version(), 0);
  EXPECT_EQ(header.m_version_and_length.internet_header_length(), 0);
  EXPECT_EQ(header.m_version_and_length.m_value, 0);

  header.m_version_and_length.set_version(0x7);
  EXPECT_EQ(header.m_version_and_length.version(), 0x7);
  EXPECT_EQ(header.m_version_and_length.internet_header_length(), 0);

  header.m_version_and_length.set_internet_header_length(0x8);
  EXPECT_EQ(header.m_version_and_length.version(), 0x7);
  EXPECT_EQ(header.m_version_and_length.internet_header_length(), 0x8);

  EXPECT_EQ(header.m_version_and_length.m_value, 0x78);
}

TEST_F(IpTest, Header_TypeOfService) {
  internet_header header;

  EXPECT_EQ(header.m_type_of_service.precedence(), 0);
  EXPECT_EQ(header.m_type_of_service.delay(), 0);
  EXPECT_EQ(header.m_type_of_service.throughput(), 0);
  EXPECT_EQ(header.m_type_of_service.reliability(), 0);
  EXPECT_EQ(header.m_type_of_service.reserved(), 0);
  EXPECT_EQ(header.m_type_of_service.m_value, 0);

  header.m_type_of_service.set_precedence(0b101);
  EXPECT_EQ(header.m_type_of_service.precedence(), 0b101);
  EXPECT_EQ(header.m_type_of_service.delay(), 0);
  EXPECT_EQ(header.m_type_of_service.throughput(), 0);
  EXPECT_EQ(header.m_type_of_service.reliability(), 0);
  EXPECT_EQ(header.m_type_of_service.reserved(), 0);
  EXPECT_EQ(header.m_type_of_service.m_value, 0b1010'0000);

  header.m_type_of_service.set_delay(1);
  EXPECT_EQ(header.m_type_of_service.precedence(), 0b101);
  EXPECT_EQ(header.m_type_of_service.delay(), 1);
  EXPECT_EQ(header.m_type_of_service.throughput(), 0);
  EXPECT_EQ(header.m_type_of_service.reliability(), 0);
  EXPECT_EQ(header.m_type_of_service.reserved(), 0);
  EXPECT_EQ(header.m_type_of_service.m_value, 0b1011'0000);

  header.m_type_of_service.set_throughput(1);
  EXPECT_EQ(header.m_type_of_service.precedence(), 0b101);
  EXPECT_EQ(header.m_type_of_service.delay(), 1);
  EXPECT_EQ(header.m_type_of_service.throughput(), 1);
  EXPECT_EQ(header.m_type_of_service.reliability(), 0);
  EXPECT_EQ(header.m_type_of_service.reserved(), 0);
  EXPECT_EQ(header.m_type_of_service.m_value, 0b1011'1000);

  header.m_type_of_service.set_reliability(1);
  EXPECT_EQ(header.m_type_of_service.precedence(), 0b101);
  EXPECT_EQ(header.m_type_of_service.delay(), 1);
  EXPECT_EQ(header.m_type_of_service.throughput(), 1);
  EXPECT_EQ(header.m_type_of_service.reliability(), 1);
  EXPECT_EQ(header.m_type_of_service.reserved(), 0);
  EXPECT_EQ(header.m_type_of_service.m_value, 0b1011'1100);

  header.m_type_of_service.set_reserved(0b01);
  EXPECT_EQ(header.m_type_of_service.precedence(), 0b101);
  EXPECT_EQ(header.m_type_of_service.delay(), 1);
  EXPECT_EQ(header.m_type_of_service.throughput(), 1);
  EXPECT_EQ(header.m_type_of_service.reliability(), 1);
  EXPECT_EQ(header.m_type_of_service.reserved(), 0b01);
  EXPECT_EQ(header.m_type_of_service.m_value, 0b1011'1101);
}

TEST_F(IpTest, Header_FlagsAndOffset) {
  internet_header header;

  EXPECT_EQ(header.m_flags_and_offset.flags(), 0);
  EXPECT_EQ(header.m_flags_and_offset.fragment_offset(), 0);
  EXPECT_EQ(header.m_flags_and_offset.m_value, 0);

  header.m_flags_and_offset.set_flags(0b101);
  EXPECT_EQ(header.m_flags_and_offset.flags(), 0b101);
  EXPECT_EQ(header.m_flags_and_offset.fragment_offset(), 0);
  EXPECT_EQ(header.m_flags_and_offset.m_value, 0b1010'0000'0000'0000);

  header.m_flags_and_offset.set_fragment_offset(0b1'0001'0010'0100);
  EXPECT_EQ(header.m_flags_and_offset.flags(), 0b101);
  EXPECT_EQ(header.m_flags_and_offset.fragment_offset(), 0b1'0001'0010'0100);
  EXPECT_EQ(header.m_flags_and_offset.m_value, 0b1011'0001'0010'0100);
}

TEST_F(IpTest, ReadInternetHeader_Basic) {
  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());
  EXPECT_EQ(got_header.value(), make_default_header());
}

TEST_F(IpTest, ReadInternetHeader_Endianess) {

  // clang-format off
  const std::array<std::uint8_t, k_min_valid_internet_header_length * 4>
      binary_header{
        0x15, 0x23, 0x34, 0x45,
        0x56, 0x67, 0x78, 0x89,
        0x90, 0x0a, 0xab, 0xbc,
        0xcd, 0xde, 0xef, 0xf1,
        0x1a, 0x2b, 0x3c, 0x4d
      };
  // clang-format on

  const auto header = read_internet_header(binary_header);
  ASSERT_TRUE(header.has_value());

  EXPECT_EQ(header->m_version_and_length.version(), 0x1);
  EXPECT_EQ(header->m_version_and_length.internet_header_length(), 0x5);

  EXPECT_EQ(header->m_type_of_service.precedence(), 0x1);
  EXPECT_EQ(header->m_type_of_service.delay(), 0);
  EXPECT_EQ(header->m_type_of_service.throughput(), 0);
  EXPECT_EQ(header->m_type_of_service.reliability(), 0);
  EXPECT_EQ(header->m_type_of_service.reserved(), 0x3);

  EXPECT_EQ(header->m_total_length, 0x3445);

  EXPECT_EQ(header->m_identification, 0x5667);

  EXPECT_EQ(header->m_flags_and_offset.flags(), 0x3);
  EXPECT_EQ(header->m_flags_and_offset.fragment_offset(), 0x1889);

  EXPECT_EQ(header->m_time_to_live, 0x90);
  EXPECT_EQ(header->m_protocol, 0x0a);
  EXPECT_EQ(header->m_header_checksum, 0xabbc);
  EXPECT_EQ(header->m_source_address, 0xcddeeff1);
  EXPECT_EQ(header->m_destination_address, 0x1a2b3c4d);
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
    header.m_version_and_length.set_internet_header_length(header_length);
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
    header.m_version_and_length.set_internet_header_length(header_length);
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
    header.m_version_and_length.set_internet_header_length(header_length);
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
    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() + 1);

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
    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() + 1);

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
    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() + 1);

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
  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 1);

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

TEST_F(IpTest, OptionsReader_CantEatLength) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_no_operation.to_uint8();
  header.m_options[1] = option::k_no_operation.to_uint8();
  header.m_options[2] = option::k_no_operation.to_uint8();

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 1);

  const std::array options_to_test{option::k_security,
                                   option::k_loose_source_routing,
                                   option::k_strict_source_routing,
                                   option::k_record_route,
                                   option::k_stream_id,
                                   option::k_internet_timestamp};

  for (const auto &to_test : options_to_test) {

    header.m_options[3] = to_test.to_uint8();

    test_print(fmt::to_string(to_test));

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

    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_FALSE(got_option.has_value());
    EXPECT_EQ(got_option.error(), option_reading_error::no_enough_data);

    EXPECT_FALSE(reader.possibly_has_options());
  }
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

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 3);

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
    // TODO decode data
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
  header.m_options[0] = option::k_no_operation.to_uint8();

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

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 3);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    EXPECT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    EXPECT_EQ(got_option.value().m_type, option::k_no_operation);
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

TEST_F(IpTest, OptionsReader_Lsrr) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_loose_source_routing.to_uint8();
  header.m_options[1] = 7; // Length
  header.m_options[2] = 4; // Pointer, 1-indexed
  // Address
  header.m_options[3] = 0x11;
  header.m_options[4] = 0x22;
  header.m_options[5] = 0x33;
  header.m_options[6] = 0x44;

  header.m_options[7] = option::k_end_of_list.to_uint8();

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    ASSERT_EQ(got_option.value().m_type, option::k_loose_source_routing);
    EXPECT_EQ(got_option.value().m_data.size(), 5); // Including pointer.

    const auto read_lsrr = options_reader::decode_routing(got_option->m_data);

    ASSERT_TRUE(read_lsrr.has_value());

    ASSERT_EQ(read_lsrr.value().m_pointer, 4);

    EXPECT_EQ(read_lsrr.value().m_data[0], 0x11);
    EXPECT_EQ(read_lsrr.value().m_data[1], 0x22);
    EXPECT_EQ(read_lsrr.value().m_data[2], 0x33);
    EXPECT_EQ(read_lsrr.value().m_data[3], 0x44);
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

TEST_F(IpTest, OptionsReader_Lsrr_TooBigLength) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_loose_source_routing.to_uint8();
  header.m_options[1] = 16; // Length, too big
  header.m_options[2] = 4;  // Pointer, 1-indexed
  // Address
  header.m_options[3] = 0x11;
  header.m_options[4] = 0x22;
  header.m_options[5] = 0x33;
  header.m_options[6] = 0x44;

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  ASSERT_TRUE(reader.possibly_has_options());
  const auto got_option = reader.try_read_next();
  ASSERT_FALSE(got_option.has_value());
  EXPECT_EQ(got_option.error(), option_reading_error::no_enough_data);

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_Lsrr_MalformedPointer) {

  for (std::uint8_t pointer = 0; pointer < 4; ++pointer) {
    test_print(fmt::format("pointer={}", pointer));

    auto header = make_default_header();

    // No-op
    header.m_options[0] = option::k_loose_source_routing.to_uint8();
    header.m_options[1] = 7; // Length
    header.m_options[2] = pointer;
    // Address
    header.m_options[3] = 0x11;
    header.m_options[4] = 0x22;
    header.m_options[5] = 0x33;
    header.m_options[6] = 0x44;

    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() + 2);

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      ASSERT_EQ(got_option.value().m_type, option::k_loose_source_routing);
      EXPECT_EQ(got_option.value().m_data.size(), 5); // Including pointer.

      const auto read_lsrr = options_reader::decode_routing(got_option->m_data);
      ASSERT_FALSE(read_lsrr.has_value());
      EXPECT_EQ(read_lsrr.error(),
                option_reading_error::malformed_pointer_value);
    }

    EXPECT_TRUE(reader.possibly_has_options());
  }
}

TEST_F(IpTest, OptionsReader_Ssrr) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_strict_source_routing.to_uint8();
  header.m_options[1] = 7; // Length
  header.m_options[2] = 4; // Pointer, 1-indexed
  // Address
  header.m_options[3] = 0x11;
  header.m_options[4] = 0x22;
  header.m_options[5] = 0x33;
  header.m_options[6] = 0x44;

  header.m_options[7] = option::k_end_of_list.to_uint8();

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    ASSERT_EQ(got_option.value().m_type, option::k_strict_source_routing);
    EXPECT_EQ(got_option.value().m_data.size(), 5); // Including pointer.

    const auto read_lsrr = options_reader::decode_routing(got_option->m_data);

    ASSERT_TRUE(read_lsrr.has_value());

    ASSERT_EQ(read_lsrr.value().m_pointer, 4);

    EXPECT_EQ(read_lsrr.value().m_data[0], 0x11);
    EXPECT_EQ(read_lsrr.value().m_data[1], 0x22);
    EXPECT_EQ(read_lsrr.value().m_data[2], 0x33);
    EXPECT_EQ(read_lsrr.value().m_data[3], 0x44);
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

TEST_F(IpTest, OptionsReader_Ssrr_TooBigLength) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_strict_source_routing.to_uint8();
  header.m_options[1] = 16; // Length, too big
  header.m_options[2] = 4;  // Pointer, 1-indexed
  // Address
  header.m_options[3] = 0x11;
  header.m_options[4] = 0x22;
  header.m_options[5] = 0x33;
  header.m_options[6] = 0x44;

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  ASSERT_TRUE(reader.possibly_has_options());
  const auto got_option = reader.try_read_next();
  ASSERT_FALSE(got_option.has_value());
  EXPECT_EQ(got_option.error(), option_reading_error::no_enough_data);

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_Ssrr_MalformedPointer) {

  for (std::uint8_t pointer = 0; pointer < 4; ++pointer) {
    test_print(fmt::format("pointer={}", pointer));

    auto header = make_default_header();

    // No-op
    header.m_options[0] = option::k_strict_source_routing.to_uint8();
    header.m_options[1] = 7; // Length
    header.m_options[2] = pointer;
    // Address
    header.m_options[3] = 0x11;
    header.m_options[4] = 0x22;
    header.m_options[5] = 0x33;
    header.m_options[6] = 0x44;

    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() + 2);

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      ASSERT_EQ(got_option.value().m_type, option::k_strict_source_routing);
      EXPECT_EQ(got_option.value().m_data.size(), 5); // Including pointer.

      const auto read_lsrr = options_reader::decode_routing(got_option->m_data);
      ASSERT_FALSE(read_lsrr.has_value());
      EXPECT_EQ(read_lsrr.error(),
                option_reading_error::malformed_pointer_value);
    }

    EXPECT_TRUE(reader.possibly_has_options());
  }
}

TEST_F(IpTest, OptionsReader_RecordRoute) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_record_route.to_uint8();
  header.m_options[1] = 7; // Length
  header.m_options[2] = 4; // Pointer, 1-indexed
  // Address
  header.m_options[3] = 0x11;
  header.m_options[4] = 0x22;
  header.m_options[5] = 0x33;
  header.m_options[6] = 0x44;

  header.m_options[7] = option::k_end_of_list.to_uint8();

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    ASSERT_EQ(got_option.value().m_type, option::k_record_route);
    EXPECT_EQ(got_option.value().m_data.size(), 5); // Including pointer.

    const auto read_lsrr = options_reader::decode_routing(got_option->m_data);

    ASSERT_TRUE(read_lsrr.has_value());

    ASSERT_EQ(read_lsrr.value().m_pointer, 4);

    EXPECT_EQ(read_lsrr.value().m_data[0], 0x11);
    EXPECT_EQ(read_lsrr.value().m_data[1], 0x22);
    EXPECT_EQ(read_lsrr.value().m_data[2], 0x33);
    EXPECT_EQ(read_lsrr.value().m_data[3], 0x44);
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

TEST_F(IpTest, OptionsReader_RecordRouting_TooBigLength) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_record_route.to_uint8();
  header.m_options[1] = 16; // Length, too big
  header.m_options[2] = 4;  // Pointer, 1-indexed
  // Address
  header.m_options[3] = 0x11;
  header.m_options[4] = 0x22;
  header.m_options[5] = 0x33;
  header.m_options[6] = 0x44;

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  ASSERT_TRUE(reader.possibly_has_options());
  const auto got_option = reader.try_read_next();
  ASSERT_FALSE(got_option.has_value());
  EXPECT_EQ(got_option.error(), option_reading_error::no_enough_data);

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_RecordRouting_MalformedPointer) {

  for (std::uint8_t pointer = 0; pointer < 4; ++pointer) {
    test_print(fmt::format("pointer={}", pointer));

    auto header = make_default_header();

    // No-op
    header.m_options[0] = option::k_record_route.to_uint8();
    header.m_options[1] = 7; // Length
    header.m_options[2] = pointer;
    // Address
    header.m_options[3] = 0x11;
    header.m_options[4] = 0x22;
    header.m_options[5] = 0x33;
    header.m_options[6] = 0x44;

    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() + 2);

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_TRUE(got_option.has_value());
      ASSERT_EQ(got_option.value().m_type, option::k_record_route);
      EXPECT_EQ(got_option.value().m_data.size(), 5); // Including pointer.

      const auto read_lsrr = options_reader::decode_routing(got_option->m_data);
      ASSERT_FALSE(read_lsrr.has_value());
      EXPECT_EQ(read_lsrr.error(),
                option_reading_error::malformed_pointer_value);
    }

    EXPECT_TRUE(reader.possibly_has_options());
  }
}

TEST_F(IpTest, OptionsReader_StreamId) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_stream_id.to_uint8();
  header.m_options[1] = option::k_stream_id_length;
  // Id
  header.m_options[2] = 0x11;
  header.m_options[3] = 0x22;

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 1);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};
  {
    ASSERT_TRUE(reader.possibly_has_options());
    const auto got_option = reader.try_read_next();
    ASSERT_TRUE(got_option.has_value());
    ASSERT_EQ(got_option.value().m_type, option::k_stream_id);
    EXPECT_EQ(got_option.value().m_data.size(), 2);
    EXPECT_EQ(got_option.value().m_data[0], 0x11);
    EXPECT_EQ(got_option.value().m_data[1], 0x22);
  }

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_TooSmallLength) {

  // Test with length too small for a valid length of given option

  struct TestValues {
    option::option_type m_type;
    std::uint8_t m_min_length = 0;
    std::uint8_t m_max_length = 0;
    option_reading_error m_malformed_length_error =
        option_reading_error::no_enough_data;
  };

  const std::array test_values{
      TestValues{option::k_stream_id, 0, option::k_stream_id_length,
                 option_reading_error::malformed_stream_id_length},
      TestValues{option::k_security, 0, option::k_security_length,
                 option_reading_error::malformed_security_length},
      TestValues{option::k_internet_timestamp, 0,
                 option::k_min_internet_timestamp_length,
                 option_reading_error::malformed_internet_timestamp_length},
  };

  for (const auto &test_value : test_values) {
    for (std::uint8_t length = test_value.m_min_length;
         length < test_value.m_max_length; ++length) {

      test_print(
          fmt::format("option={}, length={}", test_value.m_type, length));

      auto header = make_default_header();

      // Add option
      header.m_options[0] = test_value.m_type.to_uint8();
      header.m_options[1] = length;

      // End of list
      if (length < 2) {
        header.m_options[2] = option::k_end_of_list.to_uint8();
      } else {
        header.m_options[length] = option::k_end_of_list.to_uint8();
      }

      header.m_version_and_length.set_internet_header_length(
          header.m_version_and_length.internet_header_length() + 10);

      write_header(header);

      const auto got_header = read_internet_header(m_buffer);
      ASSERT_TRUE(got_header.has_value());

      options_reader reader{got_header.value()};
      {
        ASSERT_TRUE(reader.possibly_has_options());
        const auto got_option = reader.try_read_next();
        ASSERT_FALSE(got_option.has_value());
        EXPECT_EQ(got_option.error(), test_value.m_malformed_length_error);
      }
      {
        ASSERT_TRUE(reader.possibly_has_options());
        const auto got_option = reader.try_read_next();
        ASSERT_TRUE(got_option.has_value());
        EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
        EXPECT_TRUE(got_option.value().m_data.empty());
      }
    }
  }
}

TEST_F(IpTest, OptionsReader_MalformedLength_NoEnoughDataToOmit) {

  // Test case where length indicates more data than it's available in the
  // options buffer

  struct TestValues {
    option::option_type m_type;
    std::optional<std::uint8_t> m_valid_length;
    option_reading_error m_malformed_length_error =
        option_reading_error::no_enough_data;
  };

  const std::array test_values{
      TestValues{option::k_stream_id, option::k_stream_id_length,
                 option_reading_error::malformed_stream_id_length},
      TestValues{option::k_security, option::k_security_length,
                 option_reading_error::malformed_security_length},
      TestValues{option::k_internet_timestamp, std::nullopt,
                 option_reading_error::no_enough_data},
  };

  const std::uint8_t max_option_octets = 10;

  for (const auto &test_value : test_values) {
    for (std::uint8_t length = 5; length <= max_option_octets * 4; ++length) {

      if (length == test_value.m_valid_length) {
        test_print(fmt::format("option={}, length={} - omit valid length",
                               test_value.m_type, length));
        continue;
      }

      test_print(
          fmt::format("option={}, length={}", test_value.m_type, length));

      auto header = make_default_header();

      // Add option
      header.m_options[0] = test_value.m_type.to_uint8();
      header.m_options[1] = length;

      header.m_version_and_length.set_internet_header_length(
          header.m_version_and_length.internet_header_length() + 1);

      write_header(header);

      const auto got_header = read_internet_header(m_buffer);
      ASSERT_TRUE(got_header.has_value());

      options_reader reader{got_header.value()};
      {
        ASSERT_TRUE(reader.possibly_has_options());
        const auto got_option = reader.try_read_next();
        ASSERT_FALSE(got_option.has_value());
        EXPECT_EQ(got_option.error(), test_value.m_malformed_length_error);
      }
      EXPECT_FALSE(reader.possibly_has_options());
    }
  }
}

TEST_F(IpTest, OptionsReader_MalformedLength_CanOmit) {

  struct TestValues {
    option::option_type m_type;
    std::uint8_t m_valid_length = 0;
    option_reading_error m_malformed_length_error =
        option_reading_error::no_enough_data;
  };

  const std::array test_values{
      TestValues{option::k_stream_id, option::k_stream_id_length,
                 option_reading_error::malformed_stream_id_length},
      TestValues{option::k_security, option::k_security_length,
                 option_reading_error::malformed_security_length}};

  const std::uint8_t max_option_octets = 10;

  for (const auto &test_value : test_values) {

    for (std::uint8_t length = 0; length <= max_option_octets * 4 - 1;
         ++length) {

      if (length == test_value.m_valid_length) {
        test_print(fmt::format("option={}, length={} - omit valid length",
                               test_value.m_type, length));
        continue;
      }

      test_print(
          fmt::format("option={}, length={}", test_value.m_type, length));

      auto header = make_default_header();

      // Add option
      header.m_options[0] = test_value.m_type.to_uint8();
      header.m_options[1] = length;

      // End of list
      if (length < 2) {
        header.m_options[2] = option::k_end_of_list.to_uint8();
      } else {
        header.m_options[length] = option::k_end_of_list.to_uint8();
      }

      header.m_version_and_length.set_internet_header_length(
          header.m_version_and_length.internet_header_length() +
          max_option_octets);

      write_header(header);

      const auto got_header = read_internet_header(m_buffer);
      ASSERT_TRUE(got_header.has_value());

      options_reader reader{got_header.value()};
      // Get security with malformed length.
      {
        ASSERT_TRUE(reader.possibly_has_options());
        const auto got_option = reader.try_read_next();
        ASSERT_FALSE(got_option.has_value());
        EXPECT_EQ(got_option.error(), test_value.m_malformed_length_error);
      }
      // Expect end of list
      {
        ASSERT_TRUE(reader.possibly_has_options());
        const auto got_option = reader.try_read_next();
        ASSERT_TRUE(got_option.has_value());
        EXPECT_EQ(got_option.value().m_type, option::k_end_of_list);
        EXPECT_TRUE(got_option.value().m_data.empty());
      }
    }

    // Test ending exactly at header end
    test_print(fmt::format("option={}, length=40", test_value.m_type));

    auto header = make_default_header();

    // Add option
    header.m_options[0] = test_value.m_type.to_uint8();
    header.m_options[1] = 40;

    header.m_version_and_length.set_internet_header_length(
        header.m_version_and_length.internet_header_length() +
        max_option_octets);

    write_header(header);

    const auto got_header = read_internet_header(m_buffer);
    ASSERT_TRUE(got_header.has_value());

    options_reader reader{got_header.value()};
    // Get security with malformed length.
    {
      ASSERT_TRUE(reader.possibly_has_options());
      const auto got_option = reader.try_read_next();
      ASSERT_FALSE(got_option.has_value());
      EXPECT_EQ(got_option.error(), test_value.m_malformed_length_error);
    }
    EXPECT_FALSE(reader.possibly_has_options());
  }
}

TEST_F(IpTest, OptionsReader_InternetTimestamp_MinLength) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_internet_timestamp.to_uint8();
  header.m_options[1] = option::k_min_internet_timestamp_length;
  header.m_options[2] = 5; // Pointer
  header.m_options[3] = 0; // Overflow/flags

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 1);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};

  ASSERT_TRUE(reader.possibly_has_options());
  const auto got_option = reader.try_read_next();
  ASSERT_TRUE(got_option.has_value());
  ASSERT_EQ(got_option.value().m_type, option::k_internet_timestamp);

  const auto got_decoded =
      options_reader::decode_internet_timestamp(got_option.value().m_data);
  ASSERT_TRUE(got_decoded.has_value());
  EXPECT_EQ(got_decoded.value().m_pointer, 5);
  EXPECT_EQ(got_decoded.value().m_overflow_and_flags.get_overflow(), 0);
  EXPECT_EQ(got_decoded.value().m_overflow_and_flags.get_flags(),
            internet_overflow_flag::timestamp_only);
  EXPECT_TRUE(got_decoded.value().m_data.empty());

  EXPECT_FALSE(reader.possibly_has_options());
}

TEST_F(IpTest, OptionsReader_InternetTimestamp_SomeData) {

  auto header = make_default_header();

  // No-op
  header.m_options[0] = option::k_internet_timestamp.to_uint8();
  header.m_options[1] = option::k_min_internet_timestamp_length + 4;
  header.m_options[2] = 5; // Pointer

  internet_timestamp_overflow_flags overflow_flags;
  overflow_flags.set_overflow(6);
  overflow_flags.set_flags(internet_overflow_flag::address_is_prespecified);

  header.m_options[3] = overflow_flags.m_value;

  // Data
  header.m_options[4] = 'a';
  header.m_options[5] = 'b';
  header.m_options[6] = 'c';
  header.m_options[7] = 'd';

  header.m_version_and_length.set_internet_header_length(
      header.m_version_and_length.internet_header_length() + 2);

  write_header(header);

  const auto got_header = read_internet_header(m_buffer);
  ASSERT_TRUE(got_header.has_value());

  options_reader reader{got_header.value()};

  ASSERT_TRUE(reader.possibly_has_options());
  const auto got_option = reader.try_read_next();
  ASSERT_TRUE(got_option.has_value());
  ASSERT_EQ(got_option.value().m_type, option::k_internet_timestamp);

  const auto got_decoded =
      options_reader::decode_internet_timestamp(got_option.value().m_data);
  ASSERT_TRUE(got_decoded.has_value());
  EXPECT_EQ(got_decoded.value().m_pointer, 5);
  EXPECT_EQ(got_decoded.value().m_overflow_and_flags.get_overflow(), 6);
  EXPECT_EQ(got_decoded.value().m_overflow_and_flags.get_flags(),
            internet_overflow_flag::address_is_prespecified);
  ASSERT_EQ(got_decoded.value().m_data.size(), 4);
  EXPECT_EQ(got_decoded.value().m_data[0], 'a');
  EXPECT_EQ(got_decoded.value().m_data[1], 'b');
  EXPECT_EQ(got_decoded.value().m_data[2], 'c');
  EXPECT_EQ(got_decoded.value().m_data[3], 'd');

  EXPECT_FALSE(reader.possibly_has_options());
}

} // namespace cool_protocols::ip::test
