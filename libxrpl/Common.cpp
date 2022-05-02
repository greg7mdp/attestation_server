#include "Common.h"

// -------------- doctest stuff -----------------------------
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
// -------------- end of doctest stuff ----------------------


#include <openssl/crypto.h>

void secure_erase(void* dest, std::size_t bytes)
{
    OPENSSL_cleanse(dest, bytes);
}
