add_library(cool_protocols STATIC
  ip.hpp
  icmp.hpp
)

target_include_directories(cool_protocols INTERFACE ..)
target_link_libraries(cool_protocols fmt::fmt)
