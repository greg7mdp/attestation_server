#include "Seed.h"
#include "PublicKey.h"
#include "SecretKey.h"
#include "Digest.h"
#include "rngfill.h"
#include "csprng.h"


namespace xrpl {

Seed::~Seed()
{
    secure_erase(buf_.data(), buf_.size());
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


Seed
randomSeed()
{
    std::array<std::uint8_t, 16> buffer;
    beast::rngfill(buffer.data(), buffer.size(), crypto_prng());
    Seed seed(to_ustring_view(buffer));
    secure_erase(buffer.data(), buffer.size());
    return seed;
}

Seed
generateSeed(std::string const& passPhrase)
{
    sha512_half_hasher_s h;
    h(passPhrase.data(), passPhrase.size());
    auto const digest = sha512_half_hasher::result_type(h);
    return Seed({digest.data(), 16});
}

template <>
std::optional<Seed>
parseBase58(ustring_view s)
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
            return Seed{Slice(seed.data(), seed.size())};
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
    
    
} // namespace xrpl
