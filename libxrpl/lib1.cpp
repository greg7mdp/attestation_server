#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#include <boost/lambda/lambda.hpp>
#include <boost/system.hpp>
namespace sys = boost::system;

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
