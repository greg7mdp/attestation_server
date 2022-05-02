#ifndef LIBXRPL_SEED_H_INCLUDED
#define LIBXRPL_SEED_H_INCLUDED

#include "Common.h"
#include "Base58.h"

namespace xrpl {

    class Seed
    {
    private:
        std::array<uint8_t, 16> buf_;

    public:
        Seed() = delete;

        Seed(Seed const&) = default;
        Seed& operator=(Seed const&) = default;

        ~Seed();

        /** Construct a seed */
        /** @{ */
        explicit Seed(ustring_view slice);
        explicit Seed(uint128 const& seed);
        /** @} */

        constexpr ustring_view data() const
        {
            return { &buf_[0],  buf_.size() };
        }
    };

    //------------------------------------------------------------------------------

    /** Create a seed using secure random numbers. */
    Seed randomSeed();

    /** Generate a seed deterministically.

        The algorithm is specific to Ripple:

        The seed is calculated as the first 128 bits
        of the SHA512-Half of the string text excluding
        any terminating null.

        @note This will not attempt to determine the format of
        the string (e.g. hex or base58).
    */
    Seed generateSeed(std::string const& passPhrase);

    /** Parse a Base58 encoded string into a seed */
    template <>
        std::optional<Seed> parseBase58(ustring_view s);

    /** Attempt to parse a string as a seed */
    std::optional<Seed>  parseGenericSeed(ustring_view s);

    /** Encode a Seed in RFC1751 format */
    std::string seedAs1751(Seed const& seed);

    /** ripple-lib encodes seeds used to generate an Ed25519 wallet in a
     * non-standard way. */
    std::optional<Seed> parseRippleLibSeed(ustring_view s);

    /** Format a seed as a Base58 string */
    inline std::string toBase58(Seed const& seed)
    {
        return encodeBase58Token(TokenType::FamilySeed, seed.data());
    }


} // namespace xrpl

#endif // LIBXRPL_SEED_H_INCLUDED
