#ifndef LIBXRPL_SECRETKEY_H_INCLUDED
#define LIBXRPL_SECRETKEY_H_INCLUDED

#include "Base58.h"
#include "Common.h"
#include "PublicKey.h"
#include "Seed.h"

namespace xrpl {

class LIBXRPL_EXPORT SecretKey
{
private:
    std::uint8_t buf_[32];

public:
    using const_iterator = std::uint8_t const*;

    SecretKey() = default;
    SecretKey(SecretKey const&) = default;
    SecretKey& operator=(SecretKey const&) = default;

    ~SecretKey();

    SecretKey(std::array<std::uint8_t, 32> const& data);
    SecretKey(ustring_view slice);

    constexpr ustring_view view() const
    {
        return {&buf_[0], sizeof(buf_)};
    }

    std::uint8_t const* data() const
    {
        return &buf_[0];
    }

    std::size_t size() const
    {
        return sizeof(buf_);
    }

    friend bool operator==(SecretKey const& lhs, SecretKey const& rhs)
    {
        return lhs.size() == rhs.size() && std::memcmp(lhs.data(), rhs.data(), rhs.size()) == 0;
    }

    /** Convert the secret key to a hexadecimal string.
        @note The operator<< function is deliberately omitted
        to avoid accidental exposure of secret key material.
    */
    std::string to_string() const;
};

//------------------------------------------------------------------------------

/** Parse a secret key */
template <>
std::optional<SecretKey> parseBase58(TokenType type, ustring_view s);

inline ustring toBase58(TokenType type, SecretKey const& sk)
{
    return encodeBase58Token(type, sk.view());
}

/** Create a secret key using secure random numbers. */
SecretKey randomSecretKey();

/** Generate a new secret key deterministically. */
SecretKey generateSecretKey(KeyType type, Seed const& seed);

/** Derive the public key from a secret key. */
PublicKey derivePublicKey(KeyType type, SecretKey const& sk);

/** Generate a key pair deterministically.

    This algorithm is specific to Ripple:

    For secp256k1 key pairs, the seed is converted
    to a Generator and used to compute the key pair
    corresponding to ordinal 0 for the generator.
*/
std::pair<PublicKey, SecretKey> generateKeyPair(KeyType type, Seed const& seed);

/** Create a key pair using secure random numbers. */
std::pair<PublicKey, SecretKey> randomKeyPair(KeyType type);

/** Generate a signature for a message digest.
    This can only be used with secp256k1 since Ed25519's
    security properties come, in part, from how the message
    is hashed.
*/
/** @{ */
ustring signDigest(PublicKey const& pk, SecretKey const& sk, uint256 const& digest);

inline ustring signDigest(KeyType type, SecretKey const& sk, uint256 const& digest)
{
    return signDigest(derivePublicKey(type, sk), sk, digest);
}
/** @} */

/** Generate a signature for a message.
    With secp256k1 signatures, the data is first hashed with
    SHA512-Half, and the resulting digest is signed.
*/
/** @{ */
ustring sign(PublicKey const& pk, SecretKey const& sk, ustring_view message);

inline ustring sign(KeyType type, SecretKey const& sk, ustring_view message)
{
    return sign(derivePublicKey(type, sk), sk, message);
}
/** @} */

}  // namespace xrpl

#endif  // LIBXRPL_SECRETKEY_H_INCLUDED
