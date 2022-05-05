#ifndef LIBXRPL_PUBLICKEY_H_INCLUDED
#define LIBXRPL_PUBLICKEY_H_INCLUDED

#include "Common.h"
#include "Base58.h"
#include "Seed.h"

namespace xrpl {

    enum class KeyType {
        secp256k1 = 0,
            ed25519 = 1,
            };

    std::optional<KeyType>
        publicKeyType(ustring_view sv);

    class PublicKey
    {
    protected:
        std::size_t size_ = 0;
        std::uint8_t buf_[33];  // should be large enough

    public:
        using const_iterator = std::uint8_t const*;

        PublicKey() = default;
        PublicKey(PublicKey const& other);
        PublicKey& operator=(PublicKey const& other);

        /** Create a public key.

            Preconditions:
            publicKeyType(slice) != std::nullopt
        */
        explicit PublicKey(ustring_view sv);

        std::uint8_t const*
            data() const noexcept
        {
            return buf_;
        }

        std::size_t
            size() const noexcept
        {
            return size_;
        }

        constexpr ustring_view view() const
        {
            return { &buf_[0], size_ };
        }

        const_iterator
            begin() const noexcept
        {
            return buf_;
        }

        const_iterator
            cbegin() const noexcept
        {
            return buf_;
        }

        const_iterator
            end() const noexcept
        {
            return buf_ + size_;
        }

        const_iterator
            cend() const noexcept
        {
            return buf_ + size_;
        }

        bool
            empty() const noexcept
        {
            return size_ == 0;
        }
    };

/** Print the public key to a stream.
 */
    std::ostream&
        operator<<(std::ostream& os, PublicKey const& pk);

    inline bool
        operator==(PublicKey const& lhs, PublicKey const& rhs)
        {
            return lhs.size() == rhs.size() &&
            std::memcmp(lhs.data(), rhs.data(), rhs.size()) == 0;
        }

    inline bool
        operator<(PublicKey const& lhs, PublicKey const& rhs)
    {
        return std::lexicographical_compare(
            lhs.data(),
            lhs.data() + lhs.size(),
            rhs.data(),
            rhs.data() + rhs.size());
    }

    template <class Hasher>
        void
        hash_append(Hasher& h, PublicKey const& pk)
    {
        h(pk.data(), pk.size());
    }

#if 0
    template <>
        struct STExchange<STBlob, PublicKey>
    {
        explicit STExchange() = default;

        using value_type = PublicKey;

        static void
            get(std::optional<value_type>& t, STBlob const& u)
        {
            t.emplace(Slice(u.data(), u.size()));
        }

        static std::unique_ptr<STBlob>
            set(SField const& f, PublicKey const& t)
        {
            return std::make_unique<STBlob>(f, t.data(), t.size());
        }
    };
#endif

//------------------------------------------------------------------------------

    inline ustring
        toBase58(TokenType type, PublicKey const& pk)
    {
        return encodeBase58Token(type, pk.view());
    }

    template <>
        std::optional<PublicKey>
        parseBase58(TokenType type, ustring_view sv);

    enum class ECDSACanonicality { canonical, fullyCanonical };

    /** Determines the canonicality of a signature.

        A canonical signature is in its most reduced form.
        For example the R and S components do not contain
        additional leading zeroes. However, even in
        canonical form, (R,S) and (R,G-S) are both
        valid signatures for message M.

        Therefore, to prevent malleability attacks we
        define a fully canonical signature as one where:

        R < G - S

        where G is the curve order.

        This routine returns std::nullopt if the format
        of the signature is invalid (for example, the
        points are encoded incorrectly).

        @return std::nullopt if the signature fails
        validity checks.

        @note Only the format of the signature is checked,
        no verification cryptography is performed.
    */
    std::optional<ECDSACanonicality>
        ecdsaCanonicality(ustring_view sig);

    /** Returns the type of public key.

        @return std::nullopt If the public key does not
        represent a known type.
    */
    /** @{ */
    [[nodiscard]] std::optional<KeyType>
        publicKeyType(ustring_view slice);

    [[nodiscard]] inline std::optional<KeyType>
        publicKeyType(PublicKey const& publicKey)
    {
        return publicKeyType(publicKey.view());
    }
    /** @} */

    /** Verify a secp256k1 signature on the digest of a message. */
    [[nodiscard]] bool
        verifyDigest(
            PublicKey const& publicKey,
            uint256 const& digest,
            ustring_view sig,
            bool mustBeFullyCanonical = true) noexcept;

    /** Verify a signature on a message.
        With secp256k1 signatures, the data is first hashed with
        SHA512-Half, and the resulting digest is signed.
    */
    [[nodiscard]] bool
        verify(
            PublicKey const& publicKey,
            ustring_view m,
            ustring_view sig,
            bool mustBeFullyCanonical = true) noexcept;

    /** Calculate the 160-bit node ID from a node public key. */
    NodeID
        calcNodeID(PublicKey const&);

    // VFALCO This belongs in AccountID.h but
    //        is here because of header issues
    AccountID
        calcAccountID(PublicKey const& pk);    
    

} // namespace xrpl


#endif // LIBXRPL_PUBLICKEY_H_INCLUDED
