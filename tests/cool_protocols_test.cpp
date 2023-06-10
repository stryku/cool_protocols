#include "cool_protocols/ip.hpp"

#include <gtest/gtest.h>

namespace cool_protocols::ip::test {

using namespace std::literals;

TEST(CoolProtocolsTest, Foo) {

  EXPECT_EQ(sizeof(internet_header), 60);
}

} // namespace cool_protocols::ip::test
