#ifndef LIBXRPL_SECRETKEY_H_INCLUDED
#define LIBXRPL_SECRETKEY_H_INCLUDED

#include "Common.h"
#include "Base58.h"
#include "Seed.h"

namespace xrpl {

    enum class KeyType {
        secp256k1 = 0,
        ed25519 = 1,
    };

    class SecretKey
    {
    private:
        std::uint8_t buf_[32];

    public:
        using const_iterator = std::uint8_t const*;

        SecretKey() = default;
        SecretKey(SecretKey const&) = default;
        SecretKey&  operator=(SecretKey const&) = default;

        ~SecretKey();

        SecretKey(std::array<std::uint8_t, 32> const& data);
        SecretKey(ustring_view slice);

        constexpr ustring_view data() const
        {
            return { &buf_[0], sizeof(buf_) };
        }

        /** Convert the secret key to a hexadecimal string.
            @note The operator<< function is deliberately omitted
            to avoid accidental exposure of secret key material.
        */
    };

    bool operator==(SecretKey const& lhs, SecretKey const& rhs)
        {
            return lhs.data() == rhs.data();
        }

    //------------------------------------------------------------------------------

    /** Parse a secret key */
    template <>
        std::optional<SecretKey>
        parseBase58(TokenType type, ustring_view s);

    std::string toBase58(TokenType type, SecretKey const& sk)
    {
        return encodeBase58Token(type, sk.data());
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
    std::pair<PublicKey, SecretKey>
        generateKeyPair(KeyType type, Seed const& seed);

    /** Create a key pair using secure random numbers. */
    std::pair<PublicKey, SecretKey>
        randomKeyPair(KeyType type);

    /** Generate a signature for a message digest.
        This can only be used with secp256k1 since Ed25519's
        security properties come, in part, from how the message
        is hashed.
    */
    /** @{ */
    std::string signDigest(PublicKey const& pk, SecretKey const& sk, uint256 const& digest);

    std::string signDigest(KeyType type, SecretKey const& sk, uint256 const& digest)
    {
        return signDigest(derivePublicKey(type, sk), sk, digest);
    }
    /** @} */

    /** Generate a signature for a message.
        With secp256k1 signatures, the data is first hashed with
        SHA512-Half, and the resulting digest is signed.
    */
    /** @{ */
    std::string sign(PublicKey const& pk, SecretKey const& sk, ustring_view message);

    std::string sign(KeyType type, SecretKey const& sk, ustring_view message)
    {
        return sign(derivePublicKey(type, sk), sk, message);
    }
    /** @} */

} // namespace xrpl


#endif // LIBXRPL_SECRETKEY_H_INCLUDED
