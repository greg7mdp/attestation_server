#include <SecretKey.h>
#include <cstring>

#include <secp256k1.h>
#include "StrHex.h"
#include "Digest.h"
#include "rngfill.h"


//---------------------------------------------------------------------------------
namespace xrpl {

template <class = void>
secp256k1_context const*
secp256k1Context()
{
    struct holder
    {
        secp256k1_context* impl;
        holder()
            : impl(secp256k1_context_create(
                  SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        {
        }

        ~holder()
        {
            secp256k1_context_destroy(impl);
        }
    };
    static holder const h;
    return h.impl;
}

}

//---------------------------------------------------------------------------------

namespace xrpl {

SecretKey::~SecretKey()
{
    secure_erase(buf_, sizeof(buf_));
}

SecretKey::SecretKey(std::array<std::uint8_t, 32> const& key)
{
    std::memcpy(buf_, key.data(), key.size());
}

SecretKey::SecretKey(ustring_view sv)
{
    if (sv.size() != sizeof(buf_))
        LogicError("SecretKey::SecretKey: invalid size");
    std::memcpy(buf_, sv.data(), sizeof(buf_));
}

std::string
SecretKey::to_string() const
{
    return strHex(this->view());
}

namespace detail {

void
copy_uint32(std::uint8_t* out, std::uint32_t v)
{
    *out++ = v >> 24;
    *out++ = (v >> 16) & 0xff;
    *out++ = (v >> 8) & 0xff;
    *out = v & 0xff;
}

uint256
deriveDeterministicRootKey(Seed const& seed)
{
    // We fill this buffer with the seed and append a 32-bit "counter"
    // that counts how many attempts we've had to make to generate a
    // non-zero key that's less than the curve's order:
    //
    //                       1    2
    //      0                6    0
    // buf  |----------------|----|
    //      |      seed      | seq|

    std::array<std::uint8_t, 20> buf;
    std::copy(seed.view().begin(), seed.view().end(), buf.begin());

    // The odds that this loop executes more than once are neglible
    // but *just* in case someone managed to generate a key that required
    // more iterations loop a few times.
    for (std::uint32_t seq = 0; seq != 128; ++seq)
    {
        copy_uint32(buf.data() + 16, seq);

        auto const ret = sha512Half(buf);

        if (secp256k1_ec_seckey_verify(secp256k1Context(), ret.data()) == 1)
        {
            secure_erase(buf.data(), buf.size());
            return ret;
        }
    }

    Throw<std::runtime_error>("Unable to derive generator from seed");
}

//------------------------------------------------------------------------------
/** Produces a sequence of secp256k1 key pairs.

    The reference implementation of the XRP Ledger uses a custom derivation
    algorithm which enables the derivation of an entire family of secp256k1
    keypairs from a single 128-bit seed. The algorithm predates widely-used
    standards like BIP-32 and BIP-44.

    Important note to implementers:

        Using this algorithm is not required: all valid secp256k1 keypairs will
        work correctly. Third party implementations can use whatever mechanisms
        they prefer. However, implementers of wallets or other tools that allow
        users to use existing accounts should consider at least supporting this
        derivation technique to make it easier for users to 'import' accounts.

    For more details, please check out:
        https://xrpl.org/cryptographic-keys.html#secp256k1-key-derivation
 */
class Generator
{
private:
    uint256 root_;
    std::array<std::uint8_t, 33> generator_;

    uint256
    calculateTweak(std::uint32_t seq) const
    {
        // We fill the buffer with the generator, the provided sequence
        // and a 32-bit counter tracking the number of attempts we have
        // already made looking for a non-zero key that's less than the
        // curve's order:
        //                                        3    3    4
        //      0          pubGen                 3    7    1
        // buf  |---------------------------------|----|----|
        //      |            generator            | seq| cnt|

        std::array<std::uint8_t, 41> buf;
        std::copy(generator_.begin(), generator_.end(), buf.begin());
        copy_uint32(buf.data() + 33, seq);

        // The odds that this loop executes more than once are neglible
        // but we impose a maximum limit just in case.
        for (std::uint32_t subseq = 0; subseq != 128; ++subseq)
        {
            copy_uint32(buf.data() + 37, subseq);

            auto const ret = sha512Half_s(buf);

            if (secp256k1_ec_seckey_verify(secp256k1Context(), ret.data()) == 1)
            {
                secure_erase(buf.data(), buf.size());
                return ret;
            }
        }

        Throw<std::runtime_error>("Unable to derive generator from seed");
    }

public:
    explicit Generator(Seed const& seed)
        : root_(deriveDeterministicRootKey(seed))
    {
        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(
                secp256k1Context(), &pubkey, root_.data()) != 1)
            LogicError("derivePublicKey: secp256k1_ec_pubkey_create failed");

        auto len = generator_.size();

        if (secp256k1_ec_pubkey_serialize(
                secp256k1Context(),
                generator_.data(),
                &len,
                &pubkey,
                SECP256K1_EC_COMPRESSED) != 1)
            LogicError("derivePublicKey: secp256k1_ec_pubkey_serialize failed");
    }

    ~Generator()
    {
        secure_erase(root_.data(), root_.size());
        secure_erase(generator_.data(), generator_.size());
    }

    /** Generate the nth key pair. */
    std::pair<PublicKey, SecretKey>
    operator()(std::size_t ordinal) const
    {
        // Generates Nth secret key:
        auto gsk = [this, tweak = calculateTweak(ordinal)]() {
            auto rpk = root_;

            if (secp256k1_ec_seckey_tweak_add(
                    secp256k1Context(), rpk.data(), tweak.data()) == 1)
            {
                SecretKey sk{rpk.view()};
                secure_erase(rpk.data(), rpk.size());
                return sk;
            }

            LogicError("Unable to add a tweak!");
        }();

        return {derivePublicKey(KeyType::secp256k1, gsk), gsk};
    }
};

}  // namespace detail

ustring
signDigest(PublicKey const& pk, SecretKey const& sk, uint256 const& digest)
{
    if (publicKeyType(pk) != KeyType::secp256k1)
        LogicError("sign: secp256k1 required for digest signing");

    BOOST_ASSERT(sk.size() == 32);
    secp256k1_ecdsa_signature sig_imp;
    if (secp256k1_ecdsa_sign(
            secp256k1Context(),
            &sig_imp,
            reinterpret_cast<unsigned char const*>(digest.data()),
            reinterpret_cast<unsigned char const*>(sk.data()),
            secp256k1_nonce_function_rfc6979,
            nullptr) != 1)
        LogicError("sign: secp256k1_ecdsa_sign failed");

    unsigned char sig[72];
    size_t len = sizeof(sig);
    if (secp256k1_ecdsa_signature_serialize_der(
            secp256k1Context(), sig, &len, &sig_imp) != 1)
        LogicError("sign: secp256k1_ecdsa_signature_serialize_der failed");

    return ustring{sig, len};
}

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];
extern "C" {
typedef unsigned char curved25519_key[32];

void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);
int ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);
void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);
int ed25519_sign_open_batch(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);
void ed25519_randombytes_unsafe(void *out, size_t count);
}

ustring
sign(PublicKey const& pk, SecretKey const& sk, ustring_view m)
{
    auto const type = publicKeyType(pk);
    if (!type)
        LogicError("sign: invalid type");
    switch (*type)
    {
        case KeyType::ed25519: {
            ustring b(64, '\0');
            ed25519_sign(
                m.data(), m.size(), sk.data(), pk.data() + 1, b.data());
            return b;
        }
        case KeyType::secp256k1: {
            sha512_half_hasher h;
            h(m.data(), m.size());
            auto const digest = sha512_half_hasher::result_type(h);

            secp256k1_ecdsa_signature sig_imp;
            if (secp256k1_ecdsa_sign(
                    secp256k1Context(),
                    &sig_imp,
                    reinterpret_cast<unsigned char const*>(digest.data()),
                    reinterpret_cast<unsigned char const*>(sk.data()),
                    secp256k1_nonce_function_rfc6979,
                    nullptr) != 1)
                LogicError("sign: secp256k1_ecdsa_sign failed");

            unsigned char sig[72];
            size_t len = sizeof(sig);
            if (secp256k1_ecdsa_signature_serialize_der(
                    secp256k1Context(), sig, &len, &sig_imp) != 1)
                LogicError(
                    "sign: secp256k1_ecdsa_signature_serialize_der failed");

            return ustring{sig, len};
        }
        default:
            LogicError("sign: invalid type");
    }
}

#if 0
SecretKey
randomSecretKey()
{
    std::uint8_t buf[32];
    beast::rngfill(buf, sizeof(buf), crypto_prng());
    SecretKey sk(Slice{buf, sizeof(buf)});
    secure_erase(buf, sizeof(buf));
    return sk;
}
#endif

SecretKey
generateSecretKey(KeyType type, Seed const& seed)
{
    if (type == KeyType::ed25519)
    {
        auto key = sha512Half_s(seed.view());
        SecretKey sk{key.view()};
        secure_erase(key.data(), key.size());
        return sk;
    }

    if (type == KeyType::secp256k1)
    {
        auto key = detail::deriveDeterministicRootKey(seed);
        SecretKey sk{key.view()};
        secure_erase(key.data(), key.size());
        return sk;
    }

    LogicError("generateSecretKey: unknown key type");
}

PublicKey
derivePublicKey(KeyType type, SecretKey const& sk)
{
    switch (type)
    {
        case KeyType::secp256k1: {
            secp256k1_pubkey pubkey_imp;
            if (secp256k1_ec_pubkey_create(
                    secp256k1Context(),
                    &pubkey_imp,
                    reinterpret_cast<unsigned char const*>(sk.data())) != 1)
                LogicError(
                    "derivePublicKey: secp256k1_ec_pubkey_create failed");

            unsigned char pubkey[33];
            std::size_t len = sizeof(pubkey);
            if (secp256k1_ec_pubkey_serialize(
                    secp256k1Context(),
                    pubkey,
                    &len,
                    &pubkey_imp,
                    SECP256K1_EC_COMPRESSED) != 1)
                LogicError(
                    "derivePublicKey: secp256k1_ec_pubkey_serialize failed");

            return PublicKey{ustring_view{pubkey, len}};
        }
        case KeyType::ed25519: {
            unsigned char buf[33];
            buf[0] = 0xED;
            ed25519_publickey(sk.data(), &buf[1]);
            return PublicKey(ustring_view{buf, sizeof(buf)});
        }
        default:
            LogicError("derivePublicKey: bad key type");
    };
}

std::pair<PublicKey, SecretKey>
generateKeyPair(KeyType type, Seed const& seed)
{
    switch (type)
    {
        case KeyType::secp256k1: {
            detail::Generator g(seed);
            return g(0);
        }
        default:
        case KeyType::ed25519: {
            auto const sk = generateSecretKey(type, seed);
            return {derivePublicKey(type, sk), sk};
        }
    }
}

std::pair<PublicKey, SecretKey>
randomKeyPair(KeyType type)
{
    auto const sk = randomSecretKey();
    return {derivePublicKey(type, sk), sk};
}

template <>
std::optional<SecretKey>
parseBase58(TokenType type, ustring_view s)
{
    auto const result = decodeBase58Token(s, type);
    if (result.empty())
        return std::nullopt;
    if (result.size() != 32)
        return std::nullopt;
    return SecretKey(ustring_view(result));
}    
        
} // namespace xrpl
