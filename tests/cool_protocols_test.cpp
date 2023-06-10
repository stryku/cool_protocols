#include "cool_protocols/cool_protocols.hpp"
#include "fmt/core.h"

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <limits>
#include <mutex>
#include <random>
#include <string>
#include <string_view>

namespace cool_protocols::test {

using namespace std::literals;

TEST(CoolProtocolsTest, Foo) {

  EXPECT_EQ(cool_protocols::foo(), 42);
}

} // namespace cool_protocols::test
