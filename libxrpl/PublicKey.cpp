#include "PublicKey.h"
#include <boost/multiprecision/cpp_int.hpp>
#include "Digest.h"
#include "StrHex.h"
#include <Secp256k1Context.h>

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
    for (int i = 0; i < sv.size(); ++i)
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
#ifdef LATER
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

}  // namespace xrpl
