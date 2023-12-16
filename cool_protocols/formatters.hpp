#pragma once

#include "icmp.hpp"
#include "ip.hpp"

#include <fmt/format.h>

namespace cool_protocols::detail {

struct no_parse {
  constexpr auto parse(auto &ctx) const {
    return ctx.begin();
  }
};

} // namespace cool_protocols::detail

template <>
struct fmt::formatter<cool_protocols::ip::internet_header>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::internet_header &h,
                        auto &ctx) {
    return format_to(
        ctx.out(),
        "version={}, header-length={}, tos-precedence={}, tos-delay={}, "
        "tos-throughput={}, tos-reliability={}, tos-reserved={}, "
        "total-length={}, identification={}, flags={:#x}, fragment-offset={}, "
        "ttl={}, protocol={}, checksum={}, src-address={:#x}, "
        "dest-address={:#x}",
        h.m_version_and_length.version(),
        h.m_version_and_length.internet_header_length(),
        h.m_type_of_service.precedence(), h.m_type_of_service.delay(),
        h.m_type_of_service.throughput(), h.m_type_of_service.reliability(),
        h.m_type_of_service.reserved(), h.m_total_length, h.m_identification,
        h.m_flags_and_offset.flags(), h.m_flags_and_offset.fragment_offset(),
        h.m_time_to_live, h.m_protocol, h.m_header_checksum, h.m_source_address,
        h.m_destination_address);
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::option::copied>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::option::copied copied,
                        auto &ctx) {
    switch (copied) {
      case cool_protocols::ip::option::copied::not_copied:
        return format_to(ctx.out(), "not_copied");
      case cool_protocols::ip::option::copied::copied:
        return format_to(ctx.out(), "copied");
    }
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::option::classes>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::option::classes class_,
                        auto &ctx) {
    switch (class_) {
      case cool_protocols::ip::option::classes::control:
        return format_to(ctx.out(), "control");
      case cool_protocols::ip::option::classes::reserved:
        return format_to(ctx.out(), "reserved");
      case cool_protocols::ip::option::classes::debugging_and_measurement:
        return format_to(ctx.out(), "debugging_and_measurement");
      case cool_protocols::ip::option::classes::reserved2:
        return format_to(ctx.out(), "reserved2");
    }
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::option::number>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::option::number number,
                        auto &ctx) {
    switch (number) {
      case cool_protocols::ip::option::number::end_of_list:
        return format_to(ctx.out(), "end_of_list");
      case cool_protocols::ip::option::number::no_operation:
        return format_to(ctx.out(), "no_operation");
      case cool_protocols::ip::option::number::security:
        return format_to(ctx.out(), "security");
      case cool_protocols::ip::option::number::loose_source_routing:
        return format_to(ctx.out(), "loose_source_routing");
      case cool_protocols::ip::option::number::internet_timestamp:
        return format_to(ctx.out(), "internet_timestamp");
      case cool_protocols::ip::option::number::record_route:
        return format_to(ctx.out(), "record_route");
      case cool_protocols::ip::option::number::stream_id:
        return format_to(ctx.out(), "stream_id");
      case cool_protocols::ip::option::number::strict_source_routing:
        return format_to(ctx.out(), "strict_source_routing");
    }

    return format_to(ctx.out(), "?");
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::option::option_type>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::option::option_type ot,
                        auto &ctx) {
    return format_to(ctx.out(), "{}, {}, {}",
                     (cool_protocols::ip::option::copied)ot.m_copied,
                     (cool_protocols::ip::option::classes)ot.m_class,
                     (cool_protocols::ip::option::number)ot.m_number);
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::option_reading_error>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::option_reading_error err,
                        auto &ctx) {

    switch (err) {
      case cool_protocols::ip::option_reading_error::no_more_data:
        return format_to(ctx.out(), "no_more_data");
      case cool_protocols::ip::option_reading_error::no_enough_data:
        return format_to(ctx.out(), "no_enough_data");
      case cool_protocols::ip::option_reading_error::malformed_security_length:
        return format_to(ctx.out(), "malformed_security_length");
      case cool_protocols::ip::option_reading_error::malformed_stream_id_length:
        return format_to(ctx.out(), "malformed_stream_id_length");
      case cool_protocols::ip::option_reading_error::malformed_pointer_value:
        return format_to(ctx.out(), "malformed_pointer_value");
      case cool_protocols::ip::option_reading_error::
          malformed_internet_timestamp_length:
        return format_to(ctx.out(), "malformed_internet_timestamp_length");
    }

    return format_to(ctx.out(), "?");
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::internet_overflow_flag>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::ip::internet_overflow_flag err,
                        auto &ctx) {

    switch (err) {
      case cool_protocols::ip::internet_overflow_flag::timestamp_only:
        return format_to(ctx.out(), "timestamp_only");
      case cool_protocols::ip::internet_overflow_flag::
          timestamp_preceded_with_address:
        return format_to(ctx.out(), "timestamp_preceded_with_address");
      case cool_protocols::ip::internet_overflow_flag::address_is_prespecified:
        return format_to(ctx.out(), "address_is_prespecified");
    }

    return format_to(ctx.out(), "?");
  }
};

template <>
struct fmt::formatter<cool_protocols::ip::internet_header_reading_error>
    : cool_protocols::detail::no_parse {

  constexpr auto
  format(const cool_protocols::ip::internet_header_reading_error err,
         auto &ctx) {

    switch (err) {
      case cool_protocols::ip::internet_header_reading_error::no_enough_data:
        return format_to(ctx.out(), "no_enough_data");
      case cool_protocols::ip::internet_header_reading_error::malformed_length:
        return format_to(ctx.out(), "malformed_length");
    }

    return format_to(ctx.out(), "?");
  }
};

template <>
struct fmt::formatter<cool_protocols::icmp::message_type>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::icmp::message_type err,
                        auto &ctx) {

    switch (err) {
      case cool_protocols::icmp::message_type::echo_reply:
        return format_to(ctx.out(), "echo_reply");
      case cool_protocols::icmp::message_type::destination_unreachable:
        return format_to(ctx.out(), "destination_unreachable");
      case cool_protocols::icmp::message_type::source_quench:
        return format_to(ctx.out(), "source_quench");
      case cool_protocols::icmp::message_type::redirect:
        return format_to(ctx.out(), "redirect");
      case cool_protocols::icmp::message_type::echo:
        return format_to(ctx.out(), "echo");
      case cool_protocols::icmp::message_type::time_exceeded:
        return format_to(ctx.out(), "time_exceeded");
      case cool_protocols::icmp::message_type::parameter_problem:
        return format_to(ctx.out(), "parameter_problem");
      case cool_protocols::icmp::message_type::timestamp:
        return format_to(ctx.out(), "timestamp");
      case cool_protocols::icmp::message_type::timestamp_reply:
        return format_to(ctx.out(), "timestamp_reply");
      case cool_protocols::icmp::message_type::information_request:
        return format_to(ctx.out(), "information_request");
      case cool_protocols::icmp::message_type::information_reply:
        return format_to(ctx.out(), "information_reply");
    }

    return format_to(ctx.out(), "?");
  }
};

template <>
struct fmt::formatter<cool_protocols::icmp::message_reading_error>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::icmp::message_reading_error err,
                        auto &ctx) {

    switch (err) {
      case cool_protocols::icmp::message_reading_error::no_enough_data:
        return format_to(ctx.out(), "no_enough_data");
    }

    return format_to(ctx.out(), "?");
  }
};

template <>
struct fmt::formatter<cool_protocols::icmp::echo_message>
    : cool_protocols::detail::no_parse {

  constexpr auto format(const cool_protocols::icmp::echo_message &msg,
                        auto &ctx) {
    return format_to(
        ctx.out(),
        "type={}, code={}, checksum={}, identifier={}, seq_number={}, ",
        msg.m_type, msg.m_code, msg.m_checksum, msg.m_identifier,
        msg.m_seq_number);
  }
};
