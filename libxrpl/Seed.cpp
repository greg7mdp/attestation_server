#include "Seed.h"
#include "Digest.h"
#include "PublicKey.h"
#include "SecretKey.h"
#include "csprng.h"
#include "rngfill.h"
#include <doctest/doctest.h>

namespace xrpl {

Seed::~Seed()
{
    secure_erase(buf_);
}

Seed::Seed(ustring_view sv)
{
    if (sv.size() != buf_.size())
        LogicError("Seed::Seed: invalid size");
    std::memcpy(buf_.data(), sv.data(), buf_.size());
}

Seed::Seed(uint128 const& seed)
{
    if (seed.size() != buf_.size())
        LogicError("Seed::Seed: invalid size");
    std::memcpy(buf_.data(), seed.data(), buf_.size());
}

Seed randomSeed()
{
    std::array<std::uint8_t, 16> buffer;
    beast::rngfill(buffer.data(), buffer.size(), crypto_prng());
    Seed seed(to_ustring_view(buffer));
    secure_erase(buffer);
    return seed;
}

Seed generateSeed(std::string_view passPhrase)
{
    sha512_half_hasher_s h;
    h(passPhrase.data(), passPhrase.size());
    auto const digest = sha512_half_hasher::result_type(h);
    return Seed({digest.data(), 16});
}

template <>
std::optional<Seed> parseBase58(ustring_view s)
{
    auto const result = decodeBase58Token(s, TokenType::FamilySeed);
    if (result.empty())
        return std::nullopt;
    if (result.size() != 16)
        return std::nullopt;
    return Seed(ustring_view(result));
}

#if 0
std::optional<Seed>
parseGenericSeed(ustring_view str)
{
    if (str.empty())
        return std::nullopt;

    if (parseBase58<AccountID>(str) ||
        parseBase58<PublicKey>(TokenType::NodePublic, str) ||
        parseBase58<PublicKey>(TokenType::AccountPublic, str) ||
        parseBase58<SecretKey>(TokenType::NodePrivate, str) ||
        parseBase58<SecretKey>(TokenType::AccountSecret, str))
    {
        return std::nullopt;
    }

    {
        uint128 seed;

        if (seed.parseHex(str))
            return Seed{seed.view()};
    }

    if (auto seed = parseBase58<Seed>(str))
        return seed;

    {
        std::string key;
        if (RFC1751::getKeyFromEnglish(key, str) == 1)
        {
            Blob const blob(key.rbegin(), key.rend());
            return Seed{uint128{blob}};
        }
    }

    return generateSeed(str);
}

std::string
seedAs1751(Seed const& seed)
{
    std::string key;

    std::reverse_copy(seed.data(), seed.data() + 16, std::back_inserter(key));

    std::string encodedKey;
    RFC1751::getEnglishFromKey(encodedKey, key);
    return encodedKey;
}

std::optional<Seed>
parseRippleLibSeed(std::string const& s)
{
    auto const result = decodeBase58Token(s, TokenType::None);

    if (result.size() == 18 &&
        static_cast<std::uint8_t>(result[0]) == std::uint8_t(0xE1) &&
        static_cast<std::uint8_t>(result[1]) == std::uint8_t(0x4B))
        return Seed(makeSlice(result.substr(2)));

    return std::nullopt;
}
#endif

}  // namespace xrpl

// ================================== TESTS =======================================

namespace xrpl {

class Seed_test
{
    static bool equal(Seed const& lhs, Seed const& rhs)
    {
        return lhs.view() == rhs.view();
    }

public:
    void testConstruction()
    {
        // testcase("construction");

        {
            std::uint8_t src[16];

            for (std::uint8_t i = 0; i < 64; i++)
            {
                beast::rngfill(src, sizeof(src), crypto_prng());
                Seed const seed({src, sizeof(src)});
                CHECK(memcmp(seed.view().data(), src, sizeof(src)) == 0);
            }
        }

        for (int i = 0; i < 64; i++)
        {
            uint128 src;
            beast::rngfill(src.data(), src.size(), crypto_prng());
            Seed const seed(src);
            CHECK(memcmp(seed.view().data(), src.data(), src.size()) == 0);
        }
    }

    ustring testPassphrase(std::string passphrase)
    {
        auto const seed1 = generateSeed(passphrase);
        auto const seed2 = parseBase58<Seed>(toBase58(seed1));

        CHECK(static_cast<bool>(seed2));
        CHECK(equal(seed1, *seed2));
        return toBase58(seed1);
    }

    void testPassphrase()
    {
        // testcase("generation from passphrase");
        CHECK(testPassphrase("masterpassphrase") == to_ustring("snoPBrXtMeMyMHUVTgbuqAfg1SUTb"));
        CHECK(testPassphrase("Non-Random Passphrase") == to_ustring("snMKnVku798EnBwUfxeSD8953sLYA"));
        CHECK(testPassphrase("cookies excitement hand public") == to_ustring("sspUXGrmjQhq6mgc24jiRuevZiwKT"));
    }

    void testBase58()
    {
        // testcase("base58 operations");

        // Success:
        CHECK(parseBase58<Seed>(to_ustring_view("snoPBrXtMeMyMHUVTgbuqAfg1SUTb")));
        CHECK(parseBase58<Seed>(to_ustring_view("snMKnVku798EnBwUfxeSD8953sLYA")));
        CHECK(parseBase58<Seed>(to_ustring_view("sspUXGrmjQhq6mgc24jiRuevZiwKT")));

        // Failure:
        CHECK(!parseBase58<Seed>(to_ustring_view("")));
        CHECK(!parseBase58<Seed>(to_ustring_view("sspUXGrmjQhq6mgc24jiRuevZiwK")));
        CHECK(!parseBase58<Seed>(to_ustring_view("sspUXGrmjQhq6mgc24jiRuevZiwKTT")));
        CHECK(!parseBase58<Seed>(to_ustring_view("sspOXGrmjQhq6mgc24jiRuevZiwKT")));
        CHECK(!parseBase58<Seed>(to_ustring_view("ssp/XGrmjQhq6mgc24jiRuevZiwKT")));
    }

    void testRandom()
    {
        // testcase("random generation");

        for (int i = 0; i < 32; i++)
        {
            auto const seed1 = randomSeed();
            auto const seed2 = parseBase58<Seed>(toBase58(seed1));

            CHECK(static_cast<bool>(seed2));
            CHECK(equal(seed1, *seed2));
        }
    }

    void testKeypairGenerationAndSigning()
    {
        std::string const message1 = "http://www.ripple.com";
        std::string const message2 = "https://www.ripple.com";

        {
            // testcase("Node keypair generation & signing (secp256k1)");

            auto const secretKey = generateSecretKey(KeyType::secp256k1, generateSeed("masterpassphrase"));
            auto const publicKey = derivePublicKey(KeyType::secp256k1, secretKey);

            CHECK(
                toBase58(TokenType::NodePublic, publicKey) ==
                to_ustring("n94a1u4jAz288pZLtw6yFWVbi89YamiC6JBXPVUj5zmExe5fTVg9"));
            CHECK(
                toBase58(TokenType::NodePrivate, secretKey) ==
                to_ustring("pnen77YEeUd4fFKG7iycBWcwKpTaeFRkW2WFostaATy1DSupwXe"));
            CHECK(to_string(calcNodeID(publicKey)) == "7E59C17D50F5959C7B158FEC95C8F815BF653DC8");

            auto sig = sign(publicKey, secretKey, to_ustring_view(message1));
            CHECK(sig.size() != 0);
            CHECK(verify(publicKey, to_ustring_view(message1), sig));

            // Correct public key but wrong message
            CHECK(!verify(publicKey, to_ustring_view(message2), sig));

            // Verify with incorrect public key
            {
                auto const otherPublicKey = derivePublicKey(
                    KeyType::secp256k1, generateSecretKey(KeyType::secp256k1, generateSeed("otherpassphrase")));

                CHECK(!verify(otherPublicKey, to_ustring_view(message1), sig));
            }

            // Correct public key but wrong signature
            {
                // Slightly change the signature:
                if (auto ptr = sig.data())
                    ptr[sig.size() / 2]++;

                CHECK(!verify(publicKey, to_ustring_view(message1), sig));
            }
        }

#ifdef LATER  // ed25519 signing not yet supported
        {
            // testcase("Node keypair generation & signing (ed25519)");

            auto const secretKey = generateSecretKey(KeyType::ed25519, generateSeed("masterpassphrase"));
            auto const publicKey = derivePublicKey(KeyType::ed25519, secretKey);

            CHECK(toBase58(TokenType::NodePublic, publicKey) == "nHUeeJCSY2dM71oxM8Cgjouf5ekTuev2mwDpc374aLMxzDLXNmjf");
            CHECK(toBase58(TokenType::NodePrivate, secretKey) == "paKv46LztLqK3GaKz1rG2nQGN6M4JLyRtxFBYFTw4wAVHtGys36");
            CHECK(to_string(calcNodeID(publicKey)) == "AA066C988C712815CC37AF71472B7CBBBD4E2A0A");

            auto sig = sign(publicKey, secretKey, makeSlice(message1));
            CHECK(sig.size() != 0);
            CHECK(verify(publicKey, makeSlice(message1), sig));

            // Correct public key but wrong message
            CHECK(!verify(publicKey, makeSlice(message2), sig));

            // Verify with incorrect public key
            {
                auto const otherPublicKey = derivePublicKey(
                    KeyType::ed25519, generateSecretKey(KeyType::ed25519, generateSeed("otherpassphrase")));

                CHECK(!verify(otherPublicKey, makeSlice(message1), sig));
            }

            // Correct public key but wrong signature
            {
                // Slightly change the signature:
                if (auto ptr = sig.data())
                    ptr[sig.size() / 2]++;

                CHECK(!verify(publicKey, makeSlice(message1), sig));
            }
        }
#endif
        {
            // testcase("Account keypair generation & signing (secp256k1)");

            auto const [pk, sk] = generateKeyPair(KeyType::secp256k1, generateSeed("masterpassphrase"));

#ifdef LATER
            CHECK(toBase58(calcAccountID(pk).view()) == to_ustring("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"));
#endif

            CHECK(
                toBase58(TokenType::AccountPublic, pk) ==
                to_ustring("aBQG8RQAzjs1eTKFEAQXr2gS4utcDiEC9wmi7pfUPTi27VCahwgw"));
            CHECK(
                toBase58(TokenType::AccountSecret, sk) ==
                to_ustring("p9JfM6HHi64m6mvB6v5k7G2b1cXzGmYiCNJf6GHPKvFTWdeRVjh"));

            auto sig = sign(pk, sk, to_ustring_view(message1));
            CHECK(sig.size() != 0);
            CHECK(verify(pk, to_ustring_view(message1), sig));

            // Correct public key but wrong message
            CHECK(!verify(pk, to_ustring_view(message2), sig));

            // Verify with incorrect public key
            {
                auto const otherKeyPair = generateKeyPair(KeyType::secp256k1, generateSeed("otherpassphrase"));

                CHECK(!verify(otherKeyPair.first, to_ustring_view(message1), sig));
            }

            // Correct public key but wrong signature
            {
                // Slightly change the signature:
                if (auto ptr = sig.data())
                    ptr[sig.size() / 2]++;

                CHECK(!verify(pk, to_ustring_view(message1), sig));
            }
        }
#ifdef LATER  // ed25519 signing not yet supported
        {
            // testcase("Account keypair generation & signing (ed25519)");

            auto const [pk, sk] = generateKeyPair(KeyType::ed25519, generateSeed("masterpassphrase"));

            CHECK(to_string(calcAccountID(pk)) == "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf");
            CHECK(toBase58(TokenType::AccountPublic, pk) == "aKGheSBjmCsKJVuLNKRAKpZXT6wpk2FCuEZAXJupXgdAxX5THCqR");
            CHECK(toBase58(TokenType::AccountSecret, sk) == "pwDQjwEhbUBmPuEjFpEG75bFhv2obkCB7NxQsfFxM7xGHBMVPu9");

            auto sig = sign(pk, sk, to_ustring_view(message1));
            CHECK(sig.size() != 0);
            CHECK(verify(pk, to_ustring_view(message1), sig));

            // Correct public key but wrong message
            CHECK(!verify(pk, to_ustring_view(message2), sig));

            // Verify with incorrect public key
            {
                auto const otherKeyPair = generateKeyPair(KeyType::ed25519, generateSeed("otherpassphrase"));

                CHECK(!verify(otherKeyPair.first, to_ustring_view(message1), sig));
            }

            // Correct public key but wrong signature
            {
                // Slightly change the signature:
                if (auto ptr = sig.data())
                    ptr[sig.size() / 2]++;

                CHECK(!verify(pk, to_ustring_view(message1), sig));
            }
        }
#endif
    }

    void testSeedParsing()
    {
        // testcase("Parsing");

        // account IDs and node and account public and private
        // keys should not be parseable as seeds.
#ifdef LATER
        auto const node1 = randomKeyPair(KeyType::secp256k1);

        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::NodePublic, node1.first))));
        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::NodePrivate, node1.second))));

        auto const node2 = randomKeyPair(KeyType::ed25519);

        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::NodePublic, node2.first))));
        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::NodePrivate, node2.second))));

        auto const account1 = generateKeyPair(KeyType::secp256k1, randomSeed());

        CHECK(!parseGenericSeed(ustring_view(toBase58(calcAccountID(account1.first)))));
        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::AccountPublic, account1.first))));
        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::AccountSecret, account1.second))));

        auto const account2 = generateKeyPair(KeyType::ed25519, randomSeed());

        CHECK(!parseGenericSeed(ustring_view(toBase58(calcAccountID(account2.first)))));
        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::AccountPublic, account2.first))));
        CHECK(!parseGenericSeed(ustring_view(toBase58(TokenType::AccountSecret, account2.second))));
#endif
    }

    void run()
    {
        testConstruction();
        testPassphrase();
        testBase58();
        testRandom();
        testKeypairGenerationAndSigning();
        testSeedParsing();
    }
};

TEST_CASE_FIXTURE(xrpl::Seed_test, "construction")
{
    testConstruction();
}

TEST_CASE_FIXTURE(xrpl::Seed_test, "generation from passphrase")
{
    testPassphrase();
}

TEST_CASE_FIXTURE(xrpl::Seed_test, "base58 operations")
{
    testBase58();
}

TEST_CASE_FIXTURE(xrpl::Seed_test, "random generation")
{
    testRandom();
}

TEST_CASE_FIXTURE(xrpl::Seed_test, "Node keypair generation & signing")
{
    testKeypairGenerationAndSigning();
}

TEST_CASE_FIXTURE(xrpl::Seed_test, "Parsing")
{
    testSeedParsing();
}

}  // namespace xrpl
