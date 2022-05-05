#include "PublicKey.h"
#include "Digest.h"
#include "StrHex.h"
#include <Secp256k1Context.h>


namespace xrpl {


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
std::ostream&
operator<<(std::ostream& os, PublicKey const& pk)
{
    auto sv = pk.view();
    os << strHex(sv);
    return os;
}

//  ----------------------------------------------------------
bool
verifyDigest(
    PublicKey const& publicKey,
    uint256 const& digest,
    ustring_view sig,
    bool /* mustBeFullyCanonical */) noexcept
{
    if (publicKeyType(publicKey) != KeyType::secp256k1)
        LogicError("sign: secp256k1 required for digest signing");
#ifdef LATER
    auto const canonicality = ecdsaCanonicality(sig);
    if (!canonicality)
        return false;
    if (mustBeFullyCanonical &&
        (*canonicality != ECDSACanonicality::fullyCanonical))
        return false;
#endif
    
    secp256k1_pubkey pubkey_imp;
    if (secp256k1_ec_pubkey_parse(
            secp256k1Context(),
            &pubkey_imp,
            reinterpret_cast<unsigned char const*>(publicKey.data()),
            publicKey.size()) != 1)
        return false;

    secp256k1_ecdsa_signature sig_imp;
    if (secp256k1_ecdsa_signature_parse_der(
            secp256k1Context(),
            &sig_imp,
            reinterpret_cast<unsigned char const*>(sig.data()),
            sig.size()) != 1)
        return false;
#ifdef LATER
    if (*canonicality != ECDSACanonicality::fullyCanonical)
    {
        secp256k1_ecdsa_signature sig_norm;
        if (secp256k1_ecdsa_signature_normalize(
                secp256k1Context(), &sig_norm, &sig_imp) != 1)
            return false;
        return secp256k1_ecdsa_verify(
                   secp256k1Context(),
                   &sig_norm,
                   reinterpret_cast<unsigned char const*>(digest.data()),
                   &pubkey_imp) == 1;
    }
#endif
    return secp256k1_ecdsa_verify(
               secp256k1Context(),
               &sig_imp,
               reinterpret_cast<unsigned char const*>(digest.data()),
               &pubkey_imp) == 1;
}

bool
verify(
    PublicKey const& publicKey,
    ustring_view m,
    ustring_view sig,
    bool mustBeFullyCanonical) noexcept
{
    if (auto const type = publicKeyType(publicKey))
    {
        if (*type == KeyType::secp256k1)
        {
            return verifyDigest(
                publicKey, sha512Half(m), sig, mustBeFullyCanonical);
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
            return ed25519_sign_open(
                       m.data(), m.size(), publicKey.data() + 1, sig.data()) ==
                0;
        }
#endif
    }
    return false;
}

//  ----------------------------------------------------------
std::optional<KeyType>
publicKeyType(ustring_view sv)
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

} // namespace xrpl
