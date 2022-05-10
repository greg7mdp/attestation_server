
#include "PublicKey.h"
#include <boost/multiprecision/cpp_int.hpp>
#include "Digest.h"
#include "SecretKey.h"
#include "StrHex.h"
#include <Secp256k1Context.h>
#include <doctest/doctest.h>

namespace xrpl {

//------------------------------------------------------------------------------

// Parse a length-prefixed number
//  Format: 0x02 <length-byte> <number>
static std::optional<ustring_view> sigPart(ustring_view& buf)
{
    if (buf.size() < 3 || buf[0] != 0x02)
        return std::nullopt;
    auto const len = buf[1];
    buf.remove_prefix(2);
    if (len > buf.size() || len < 1 || len > 33)
        return std::nullopt;
    // Can't be negative
    if ((buf[0] & 0x80) != 0)
        return std::nullopt;
    if (buf[0] == 0)
    {
        // Can't be zero
        if (len == 1)
            return std::nullopt;
        // Can't be padded
        if ((buf[1] & 0x80) == 0)
            return std::nullopt;
    }
    std::optional<ustring_view> number = ustring_view(buf.data(), len);
    buf.remove_prefix(len);
    return number;
}

static std::string sliceToHex(ustring_view sv)
{
    std::string s;
    if (sv[0] & 0x80)
    {
        s.reserve(2 * (sv.size() + 2));
        s = "0x00";
    }
    else
    {
        s.reserve(2 * (sv.size() + 1));
        s = "0x";
    }
    for (size_t i = 0; i < sv.size(); ++i)
    {
        s += "0123456789ABCDEF"[((sv[i] & 0xf0) >> 4)];
        s += "0123456789ABCDEF"[((sv[i] & 0x0f) >> 0)];
    }
    return s;
}

/** Determine whether a signature is canonical.
    Canonical signatures are important to protect against signature morphing
    attacks.
    @param vSig the signature data
    @param sigLen the length of the signature
    @param strict_param whether to enforce strictly canonical semantics

    @note For more details please see:
    https://xrpl.org/transaction-malleability.html
    https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
    https://github.com/sipa/bitcoin/commit/58bc86e37fda1aec270bccb3df6c20fbd2a6591c
*/
std::optional<ECDSACanonicality> ecdsaCanonicality(ustring_view sig)
{
    using uint264 = boost::multiprecision::number<
        boost::multiprecision::
            cpp_int_backend<264, 264, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked, void>>;

    static uint264 const G("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    // The format of a signature should be:
    // <30> <len> [ <02> <lenR> <R> ] [ <02> <lenS> <S> ]
    if ((sig.size() < 8) || (sig.size() > 72))
        return std::nullopt;
    if ((sig[0] != 0x30) || (sig[1] != (sig.size() - 2)))
        return std::nullopt;
    ustring_view p = sig;
    p.remove_prefix(2);
    auto r = sigPart(p);
    auto s = sigPart(p);
    if (!r || !s || !p.empty())
        return std::nullopt;

    uint264 R(sliceToHex(*r));
    if (R >= G)
        return std::nullopt;

    uint264 S(sliceToHex(*s));
    if (S >= G)
        return std::nullopt;

    // (R,S) and (R,G-S) are canonical,
    // but is fully canonical when S <= G-S
    auto const Sp = G - S;
    if (S > Sp)
        return ECDSACanonicality::canonical;
    return ECDSACanonicality::fullyCanonical;
}

static bool ed25519Canonical(ustring_view sig)
{
    if (sig.size() != 64)
        return false;
    // Big-endian Order, the Ed25519 subgroup order
    std::uint8_t const Order[] = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xDE, 0xF9, 0xDE, 0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED,
    };
    // Take the second half of signature
    // and byte-reverse it to big-endian.
    auto const le = sig.data() + 32;
    std::uint8_t S[32];
    std::reverse_copy(le, le + 32, S);
    // Must be less than Order
    return std::lexicographical_compare(S, S + 32, Order, Order + 32);
}

//-------------------------------------------------------------

PublicKey::PublicKey(ustring_view sv)
{
    if (!publicKeyType(sv))
        LogicError("PublicKey::PublicKey invalid type");
    size_ = sv.size();
    std::memcpy(buf_, sv.data(), size_);
}

PublicKey::PublicKey(PublicKey const& other) : size_(other.size_)
{
    if (size_)
        std::memcpy(buf_, other.buf_, size_);
};

PublicKey& PublicKey::operator=(PublicKey const& other)
{
    size_ = other.size_;
    if (size_)
        std::memcpy(buf_, other.buf_, size_);
    return *this;
}

//  ----------------------------------------------------------
std::ostream& operator<<(std::ostream& os, PublicKey const& pk)
{
    auto sv = pk.view();
    os << strHex(sv);
    return os;
}

//  ----------------------------------------------------------
bool verifyDigest(
    PublicKey const& publicKey,
    uint256 const& digest,
    ustring_view sig,
    bool mustBeFullyCanonical) noexcept
{
    if (publicKeyType(publicKey) != KeyType::secp256k1)
        LogicError("sign: secp256k1 required for digest signing");
    auto const canonicality = ecdsaCanonicality(sig);
    if (!canonicality)
        return false;
    if (mustBeFullyCanonical && (*canonicality != ECDSACanonicality::fullyCanonical))
        return false;

    secp256k1_pubkey pubkey_imp;
    if (secp256k1_ec_pubkey_parse(
            secp256k1Context(),
            &pubkey_imp,
            reinterpret_cast<unsigned char const*>(publicKey.data()),
            publicKey.size()) != 1)
        return false;

    secp256k1_ecdsa_signature sig_imp;
    if (secp256k1_ecdsa_signature_parse_der(
            secp256k1Context(), &sig_imp, reinterpret_cast<unsigned char const*>(sig.data()), sig.size()) != 1)
        return false;
    if (*canonicality != ECDSACanonicality::fullyCanonical)
    {
        secp256k1_ecdsa_signature sig_norm;
        if (secp256k1_ecdsa_signature_normalize(secp256k1Context(), &sig_norm, &sig_imp) != 1)
            return false;
        return secp256k1_ecdsa_verify(
                   secp256k1Context(), &sig_norm, reinterpret_cast<unsigned char const*>(digest.data()), &pubkey_imp) ==
            1;
    }
    return secp256k1_ecdsa_verify(
               secp256k1Context(), &sig_imp, reinterpret_cast<unsigned char const*>(digest.data()), &pubkey_imp) == 1;
}

bool verify(PublicKey const& publicKey, ustring_view m, ustring_view sig, bool mustBeFullyCanonical) noexcept
{
    if (auto const type = publicKeyType(publicKey))
    {
        if (*type == KeyType::secp256k1)
        {
            return verifyDigest(publicKey, sha512Half(m), sig, mustBeFullyCanonical);
        }
#ifdef LATER  // ed25519 not supported yet
        else if (*type == KeyType::ed25519)
        {
            if (!ed25519Canonical(sig))
                return false;

            // We internally prefix Ed25519 keys with a 0xED
            // byte to distinguish them from secp256k1 keys
            // so when verifying the signature, we need to
            // first strip that prefix.
            return ed25519_sign_open(m.data(), m.size(), publicKey.data() + 1, sig.data()) == 0;
        }
#endif
    }
    return false;
}

//  ----------------------------------------------------------
NodeID calcNodeID(PublicKey const& pk)
{
    static_assert(NodeID::num_bytes == sizeof(ripesha_hasher::result_type));

    ripesha_hasher h;
    h(pk.view());
    return NodeID{static_cast<ripesha_hasher::result_type>(h)};
}

#if 0
AccountID calcAccountID(PublicKey const& pk)
{
    static_assert(AccountID::num_bytes == sizeof(ripesha_hasher::result_type));

    ripesha_hasher rsh;
    rsh(pk.view());
    return AccountID{static_cast<ripesha_hasher::result_type>(rsh)};
}
#endif

//  ----------------------------------------------------------
std::optional<KeyType> publicKeyType(ustring_view sv)
{
    if (sv.size() == 33)
    {
        if (sv[0] == 0xED)
            return KeyType::ed25519;

        if (sv[0] == 0x02 || sv[0] == 0x03)
            return KeyType::secp256k1;
    }

    return std::nullopt;
}

template <>
std::optional<PublicKey> parseBase58(TokenType type, ustring_view s)
{
    auto const result = decodeBase58Token(s, type);
    auto const pks = ustring_view(result);
    if (!publicKeyType(pks))
        return std::nullopt;
    return PublicKey(pks);
}

}  // namespace xrpl

// ================================== TESTS =======================================

namespace xrpl {

class PublicKey_test
{
public:
    using blob = std::vector<std::uint8_t>;

    template <class FwdIter, class Container>
    static void hex_to_binary(FwdIter first, FwdIter last, Container& out)
    {
        struct Table
        {
            int val[256];
            Table()
            {
                std::fill(val, val + 256, 0);
                for (int i = 0; i < 10; ++i)
                    val['0' + i] = i;
                for (int i = 0; i < 6; ++i)
                {
                    val['A' + i] = 10 + i;
                    val['a' + i] = 10 + i;
                }
            }
            int operator[](int i)
            {
                return val[i];
            }
        };

        static Table lut;
        out.reserve(std::distance(first, last) / 2);
        while (first != last)
        {
            auto const hi(lut[(*first++)]);
            auto const lo(lut[(*first++)]);
            out.push_back((hi * 16) + lo);
        }
    }

    blob sig(std::string const& hex)
    {
        blob b;
        hex_to_binary(hex.begin(), hex.end(), b);
        return b;
    }

    bool check(std::optional<ECDSACanonicality> answer, std::string const& s)
    {
        return ecdsaCanonicality(to_ustring_view(sig(s))) == answer;
    }

    void testCanonical()
    {
        // testcase("Canonical");

        // Fully canonical
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3045"
            "022100FF478110D1D4294471EC76E0157540C2181F47DEBD25D7F9E7DDCCCD47EE"
            "E905"
            "0220078F07CDAE6C240855D084AD91D1479609533C147C93B0AEF19BC9724D003F"
            "28"));
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3045"
            "0221009218248292F1762D8A51BE80F8A7F2CD288D810CE781D5955700DA1684DF"
            "1D2D"
            "022041A1EE1746BFD72C9760CC93A7AAA8047D52C8833A03A20EAAE92EA19717B4"
            "54"));
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3044"
            "02206A9E43775F73B6D1EC420E4DDD222A80D4C6DF5D1BEECC431A91B63C928B75"
            "81"
            "022023E9CC2D61DDA6F73EAA6BCB12688BEB0F434769276B3127E4044ED895C9D9"
            "6B"));
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3044"
            "022056E720007221F3CD4EFBB6352741D8E5A0968D48D8D032C2FBC4F6304AD1D0"
            "4E"
            "02201F39EB392C20D7801C3E8D81D487E742FA84A1665E923225BD6323847C7187"
            "9F"));
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3045"
            "022100FDFD5AD05518CEA0017A2DCB5C4DF61E7C73B6D3A38E7AE93210A1564E8C"
            "2F12"
            "0220214FF061CCC123C81D0BB9D0EDEA04CD40D96BF1425D311DA62A7096BB18EA"
            "18"));

        // Canonical but not fully canonical
        CHECK(check(
            ECDSACanonicality::canonical,
            "3046"
            "022100F477B3FA6F31C7CB3A0D1AD94A231FDD24B8D78862EE334CEA7CD08F6CBC"
            "0A1B"
            "022100928E6BCF1ED2684679730C5414AEC48FD62282B090041C41453C1D064AF5"
            "97A1"));
        CHECK(check(
            ECDSACanonicality::canonical,
            "3045"
            "022063E7C7CA93CB2400E413A342C027D00665F8BAB9C22EF0A7B8AE3AAF092230"
            "B6"
            "0221008F2E8BB7D09521ABBC277717B14B93170AE6465C5A1B36561099319C4BEB"
            "254C"));
        CHECK(check(
            ECDSACanonicality::canonical,
            "3046"
            "02210099DCA1188663DDEA506A06A7B20C2B7D8C26AFF41DECE69D6C5F7C967D32"
            "625F"
            "022100897658A6B1F9EEE5D140D7A332DA0BD73BB98974EA53F6201B01C1B594F2"
            "86EA"));
        CHECK(check(
            ECDSACanonicality::canonical,
            "3045"
            "02200855DE366E4E323AA2CE2A25674401A7D11F72EC432770D07F7B57DF7387AE"
            "C0"
            "022100DA4C6ADDEA14888858DE2AC5B91ED9050D6972BB388DEF582628CEE32869"
            "AE35"));

        // valid
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3006"
            "020101"
            "020102"));
        CHECK(check(
            ECDSACanonicality::fullyCanonical,
            "3044"
            "02203932c892e2e550f3af8ee4ce9c215a87f9bb831dcac87b2838e2c2eaa891df"
            "0c"
            "022030b61dd36543125d56b9f9f3a1f53189e5af33cdda8d77a5209aec03978fa0"
            "01"));
        CHECK(check(
            ECDSACanonicality::canonical,
            "3045"
            "0220076045be6f9eca28ff1ec606b833d0b87e70b2a630f5e3a496b110967a40f9"
            "0a"
            "0221008fffd599910eefe00bc803c688eca1d2ba7f6b180620eaa03488e6585db6"
            "ba01"));
        CHECK(check(
            ECDSACanonicality::canonical,
            "3046"
            "022100876045be6f9eca28ff1ec606b833d0b87e70b2a630f5e3a496b110967a40"
            "f90a"
            "0221008fffd599910eefe00bc803c688c2eca1d2ba7f6b180620eaa03488e6585d"
            "b6ba"));

        CHECK(check(
            std::nullopt,
            "3005"
            "0201FF"
            "0200"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020101"
            "020202"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020701"
            "020102"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020401"
            "020102"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020501"
            "020102"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020201"
            "020102"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020301"
            "020202"));
        CHECK(check(
            std::nullopt,
            "3006"
            "020401"
            "020202"));
        CHECK(check(
            std::nullopt,
            "3047"
            "0221005990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba"
            "6105"
            "022200002d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e56"
            "6695ed"));
        CHECK(check(
            std::nullopt,
            "3144"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "3045"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "301F"
            "01205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1"));
        CHECK(check(
            std::nullopt,
            "3045"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed00"));
        CHECK(check(
            std::nullopt,
            "3044"
            "01205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "3024"
            "0200"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "3044"
            "02208990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "3045"
            "0221005990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba"
            "6105"
            "02202d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "3044"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05012"
            "02d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695e"
            "d"));
        CHECK(check(
            std::nullopt,
            "3024"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "0200"));
        CHECK(check(
            std::nullopt,
            "3044"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "0220fd5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e566695"
            "ed"));
        CHECK(check(
            std::nullopt,
            "3045"
            "02205990e0584b2b238e1dfaad8d6ed69ecc1a4a13ac85fc0b31d0df395eb1ba61"
            "05"
            "0221002d5876262c288beb511d061691bf26777344b702b00f8fe28621fe4e5666"
            "95ed"));
    }

    void testBase58(KeyType keyType)
    {
        // Try converting short, long and malformed data
        CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, to_ustring_view("")));
        CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, to_ustring_view(" ")));
        CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, to_ustring_view("!ty89234gh45")));

        auto const good = toBase58(TokenType::NodePublic, derivePublicKey(keyType, randomSecretKey()));

        // Short (non-empty) strings
        {
            auto s = good;

            // Remove all characters from the string in random order:
            std::hash<ustring> r;

            while (!s.empty())
            {
                s.erase(r(s) % s.size(), 1);
                CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, s));
            }
        }

        // Long strings
        for (std::size_t i = 1; i != 16; i++)
        {
            auto s = good;
            s.resize(s.size() + i, s[i % s.size()]);
            CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, s));
        }

        // Strings with invalid Base58 characters
        for (auto c : std::string("0IOl"))
        {
            for (std::size_t i = 0; i != good.size(); ++i)
            {
                auto s = good;
                s[i % s.size()] = c;
                CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, s));
            }
        }

        // Strings with incorrect prefix
        {
            auto s = good;

            for (auto c : std::string("apsrJqtv7"))
            {
                s[0] = c;
                CHECK(!parseBase58<PublicKey>(TokenType::NodePublic, s));
            }
        }

        // Try some random secret keys
        std::array<PublicKey, 32> keys;

        for (std::size_t i = 0; i != keys.size(); ++i)
            keys[i] = derivePublicKey(keyType, randomSecretKey());

        for (std::size_t i = 0; i != keys.size(); ++i)
        {
            auto const si = toBase58(TokenType::NodePublic, keys[i]);
            CHECK(!si.empty());

            auto const ski = parseBase58<PublicKey>(TokenType::NodePublic, si);
            bool check_same = ski && (keys[i] == *ski);
            CHECK(check_same);

            for (std::size_t j = i; j != keys.size(); ++j)
            {
                CHECK((keys[i] == keys[j]) == (i == j));

                auto const sj = toBase58(TokenType::NodePublic, keys[j]);

                CHECK((si == sj) == (i == j));

                auto const skj = parseBase58<PublicKey>(TokenType::NodePublic, sj);
                bool check_same1 = skj && (keys[j] == *skj);
                CHECK(check_same1);

                bool check_same2 = (*ski == *skj) == (i == j);
                CHECK(check_same2);
            }
        }
    }

    void testBase58()
    {
        // testcase("Base58: secp256k1");

        {
            auto const pk1 = derivePublicKey(
                KeyType::secp256k1, generateSecretKey(KeyType::secp256k1, generateSeed("masterpassphrase")));

            auto const pk2 = parseBase58<PublicKey>(
                TokenType::NodePublic, to_ustring_view("n94a1u4jAz288pZLtw6yFWVbi89YamiC6JBXPVUj5zmExe5fTVg9"));
            CHECK(pk2);

            CHECK(pk1 == *pk2);
        }

        testBase58(KeyType::secp256k1);

        // testcase("Base58: ed25519");
#ifdef LATER  // ed25519 not supported yet
        {
            auto const pk1 = derivePublicKey(
                KeyType::ed25519, generateSecretKey(KeyType::ed25519, generateSeed("masterpassphrase")));

            auto const pk2 = parseBase58<PublicKey>(
                TokenType::NodePublic, to_ustring_view("nHUeeJCSY2dM71oxM8Cgjouf5ekTuev2mwDpc374aLMxzDLXNmjf"));
            CHECK(pk2);

            CHECK(pk1 == *pk2);
        }

        testBase58(KeyType::ed25519);
#endif
    }

    void testMiscOperations()
    {
        // testcase("Miscellaneous operations");

        auto const pk1 = derivePublicKey(
            KeyType::secp256k1, generateSecretKey(KeyType::secp256k1, generateSeed("masterpassphrase")));

        PublicKey pk2(pk1);
        CHECK(pk1 == pk2);
        CHECK(pk2 == pk1);

        PublicKey pk3;
        pk3 = pk2;
        CHECK(pk3 == pk2);
        CHECK(pk1 == pk3);
    }

    void run()
    {
        testBase58();
        testCanonical();
        testMiscOperations();
    }
};

}  // namespace xrpl

TEST_CASE_FIXTURE(xrpl::PublicKey_test, "Base58")
{
    testBase58();
}

TEST_CASE_FIXTURE(xrpl::PublicKey_test, "Canonical")
{
    testCanonical();
}

TEST_CASE_FIXTURE(xrpl::PublicKey_test, "Miscellaneous operations")
{
    testMiscOperations();
}

// ================================== TESTS =======================================
