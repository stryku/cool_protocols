enable_testing()

add_executable(cool_protocols_test
  cool_protocols_test.cpp)

target_link_libraries(cool_protocols_test cool_protocols gtest_main)
