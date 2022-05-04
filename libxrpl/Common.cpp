#include "Common.h"
#include <cstdlib>
#include <exception>
#include <iostream>

// -------------- doctest stuff -----------------------------
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
// -------------- end of doctest stuff ----------------------


#include <openssl/crypto.h>
#include <boost/endian/conversion.hpp>

namespace xrpl {

// ---------------- secure_erase ---------------------
void secure_erase(void* dest, std::size_t bytes)
{
    OPENSSL_cleanse(dest, bytes);
}


// ---------------- error ---------------------
namespace detail {

    [[noreturn]] void
    accessViolation() noexcept
    {
        // dereference memory location zero
        int volatile* j = 0;
        (void)*j;
        std::abort();
    }

}  // namespace detail

void
LogThrow(std::string const& )
{
    //JLOG(debugLog().warn()) << title;
}

[[noreturn]] void
LogicError(std::string const& s) noexcept
{
    //JLOG(debugLog().fatal()) << s;
    std::cerr << "Logic error: " << s << std::endl;
    detail::accessViolation();
}

// ---------------- strHex  ---------------------
int charUnHex(unsigned char c)
{
    static constexpr std::array<int, 256> const xtab = []() {
        std::array<int, 256> t{};

        for (auto& x : t)
            x = -1;

        for (int i = 0; i < 10; ++i)
            t['0' + i] = i;

        for (int i = 0; i < 6; ++i)
        {
            t['A' + i] = 10 + i;
            t['a' + i] = 10 + i;
        }

        return t;
    }();

    return xtab[c];
}



} // namespace xrpl

