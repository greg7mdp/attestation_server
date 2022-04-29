#include "lib1.h"
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include <doctest/doctest.h>

DOCTEST_SYMBOL_IMPORT void from_dll();

using namespace lib1;

int fact(int n) {
    return n <= 1 ? n : fact(n - 1) * n;
}
TEST_CASE("testing the factorial function") {
    CHECK(fact(0) == 1); // should fail
    CHECK(fact(1) == 1);
    CHECK(fact(2) == 2);
    CHECK(fact(3) == 6);
    CHECK(fact(10) == 3628800);
}


int
main(int argc, char** argv)
{
    // doctest stuff
    // -------------
    doctest::Context ctx;
    ctx.setOption("abort-after", 5);  // default - stop after 5 failed asserts
    ctx.applyCommandLine(argc, argv); // apply command line - argc / argv
    ctx.setOption("no-breaks", true); // override - don't break in the debugger
    int res = ctx.run();              // run test cases unless with --no-run
    if(ctx.shouldExit())              // query flags (and --exit) rely on this
        return res;                   // propagate the result of the tests


    // start actual work
    // -----------------
    hello hello{};
    int32_t error_code = hello.saySomething("Hello Modern C++ Development");
    if (error_code > 0)
    {
        return error_code;
    }
#ifdef WITH_OPENSSL
    error_code = hello.saySomethingHashed("Hello Modern C++ Development");
    if (error_code > 0)
    {
        return error_code;
    }
#endif
    return 0;
}
