enable_testing()

add_executable(cool_protocols_test
  ip_test.cpp
  icmp_test.cpp)

target_link_libraries(cool_protocols_test cool_protocols gtest_main)
