// ------- doctest stuff ---------------------
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include <doctest/doctest.h>

DOCTEST_SYMBOL_IMPORT void from_dll();
// ------- end of doctest stuff --------------

// using namespace xrpl;

int main(int argc, char** argv)
{
    // doctest stuff
    // -------------
    doctest::Context ctx;
    ctx.setOption("abort-after", 5);   // default - stop after 5 failed asserts
    ctx.applyCommandLine(argc, argv);  // apply command line - argc / argv
    ctx.setOption("no-breaks", true);  // override - don't break in the debugger
    int res = ctx.run();               // run test cases unless with --no-run
    if (ctx.shouldExit())              // query flags (and --exit) rely on this
        return res;                    // propagate the result of the tests

    // start actual work
    // -----------------
    return 0;
}

TEST_CASE("Attestation Server tests")
{
}
