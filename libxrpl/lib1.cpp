#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <boost/lambda/lambda.hpp>
#include <boost/system.hpp>
namespace sys = boost::system;















#if 0

#include <boost/asio.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <iostream>

using boost::asio::awaitable;
using boost::asio::buffer;
using boost::asio::co_spawn;
using boost::asio::detached;
using boost::asio::experimental::as_tuple;
using boost::asio::experimental::channel;
using boost::asio::io_context;
using boost::asio::ip::tcp;
using boost::asio::steady_timer;
using boost::asio::use_awaitable;
namespace this_coro = boost::asio::this_coro;
using namespace boost::asio::experimental::awaitable_operators;
using namespace std::literals::chrono_literals;

using token_channel = channel<void(boost::system::error_code, std::size_t)>;

awaitable<void> produce_tokens(std::size_t bytes_per_token,
    steady_timer::duration token_interval, token_channel& tokens)
{
  steady_timer timer(co_await this_coro::executor);
  for (;;)
  {
    co_await tokens.async_send(
        boost::system::error_code{}, bytes_per_token,
        use_awaitable);

    timer.expires_after(token_interval);
    co_await timer.async_wait(use_awaitable);
  }
}

#endif






#include <string>

static int fact(int n) {
    return n <= 1 ? n : fact(n - 1) * n;
}

TEST_CASE("testing the factorial function") {
    CHECK(fact(0) == 1); // should fail
    CHECK(fact(1) == 1);
    CHECK(fact(2) == 2);
    CHECK(fact(3) == 6);
    CHECK(fact(10) == 3628800);
}

DOCTEST_SYMBOL_EXPORT void from_dll();   // to silence "-Wmissing-declarations" with GCC
DOCTEST_SYMBOL_EXPORT void from_dll() {} // force the creation of a .lib file with MSVC

#include "lib1.h"

#include <iostream>

#ifdef WITH_OPENSSL
#include <openssl/sha.h>

#include <array>
#include <iomanip>
#include <sstream>
#endif

using namespace xrpl;

int32_t
hello::saySomething(const std::string& something) const noexcept
{
    if (something.empty())
    {
        std::cerr << "No value passed\n";
        return 1;
    }

    std::cout << something << '\n';
    return 0;
}

#ifdef WITH_OPENSSL
int32_t
hello::saySomethingHashed(const std::string& something) const noexcept
{
    if (something.empty())
    {
        std::cerr << "No value passed\n";
        return 1;
    }

    SHA256_CTX context;
    if (!SHA256_Init(&context))
    {
        std::cerr << "Failed to initialize context\n";
        return 2;
    }

    if (!SHA256_Update(
            &context, (unsigned char*)something.c_str(), something.size()))
    {
        std::cerr << "Failed to create hash value\n";
        return 3;
    }

    std::array<unsigned char, 32> buffer{};
    if (!SHA256_Final(buffer.data(), &context))
    {
        std::cerr << "Failed to finalize hash result\n";
        return 4;
    }

    // Transform byte-array to string
    std::stringstream shastr;
    shastr << std::hex << std::setfill('0');
    for (const auto& byte : buffer)
    {
        shastr << std::setw(2) << (int)byte;
    }

    std::cout << shastr.str() << '\n';
    return 0;
}
#endif
