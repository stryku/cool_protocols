add_executable(example_read_all read_all.cpp)

target_link_libraries(example_read_all cool_protocols)

add_executable(example_hex_to_ip hex_to_ip.cpp)
target_link_libraries(example_hex_to_ip cool_protocols)

add_executable(ping ping.cpp)
target_link_libraries(ping cool_protocols)
