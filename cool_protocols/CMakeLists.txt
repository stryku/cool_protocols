add_library(cool_protocols STATIC
  cool_protocols.hpp cool_protocols.cpp
)

target_include_directories(cool_protocols INTERFACE ..)
target_link_libraries(cool_protocols fmt::fmt)
