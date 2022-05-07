#include "Common.h"
#include <cstdlib>
#include <exception>
#include <iostream>

#include "Base58.h"
#include "Digest.h"
#include "PublicKey.h"


// -------------- doctest stuff -----------------------------
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
// -------------- end of doctest stuff ----------------------


#include <openssl/crypto.h>
#include <boost/endian/conversion.hpp>

namespace xrpl {

// ---------------- secure_erase ---------------------
void secure_erase(void* dest, std::size_t bytes)
{
    OPENSSL_cleanse(dest, bytes);
}

void secure_erase(ustring& sv)
{
    OPENSSL_cleanse(sv.data(), sv.size());
}



// ---------------- error ---------------------
namespace detail {

    [[noreturn]] void
    accessViolation() noexcept
    {
        // dereference memory location zero
        int volatile* j = 0;
        (void)*j;
        std::abort();
    }

}  // namespace detail

void
LogThrow(std::string const& )
{
    //JLOG(debugLog().warn()) << title;
}

[[noreturn]] void
LogicError(std::string const& s) noexcept
{
    //JLOG(debugLog().fatal()) << s;
    std::cerr << "Logic error: " << s << std::endl;
    detail::accessViolation();
}

// ---------------- strHex  ---------------------
int charUnHex(unsigned char c)
{
    static constexpr std::array<int, 256> const xtab = []() {
        std::array<int, 256> t{};

        for (auto& x : t)
            x = -1;

        for (int i = 0; i < 10; ++i)
            t['0' + i] = i;

        for (int i = 0; i < 6; ++i)
        {
            t['A' + i] = 10 + i;
            t['a' + i] = 10 + i;
        }

        return t;
    }();

    return xtab[c];
}

// ---------------- AccountID  ---------------------
ustring toBase58(AccountID const& v)
{
    return encodeBase58Token(TokenType::AccountID, v.view());
}

template <>
std::optional<AccountID>
parseBase58(ustring_view s)
{
    auto const result = decodeBase58Token(s, TokenType::AccountID);
    if (result.size() != AccountID::num_bytes)
        return std::nullopt;
    return AccountID{result};
}

//------------------------------------------------------------------------------
/*
    Calculation of the Account ID

    The AccountID is a 160-bit identifier that uniquely
    distinguishes an account. The account may or may not
    exist in the ledger. Even for accounts that are not in
    the ledger, cryptographic operations may be performed
    which affect the ledger. For example, designating an
    account not in the ledger as a regular key for an
    account that is in the ledger.

    Why did we use half of SHA512 for most things but then
    SHA256 followed by RIPEMD160 for account IDs? Why didn't
    we do SHA512 half then RIPEMD160? Or even SHA512 then RIPEMD160?
    For that matter why RIPEMD160 at all why not just SHA512 and keep
    only 160 bits?

    Answer (David Schwartz):

        The short answer is that we kept Bitcoin's behavior.
        The longer answer was that:
            1) Using a single hash could leave ripple
               vulnerable to length extension attacks.
            2) Only RIPEMD160 is generally considered safe at 160 bits.

        Any of those schemes would have been acceptable. However,
        the one chosen avoids any need to defend the scheme chosen.
        (Against any criticism other than unnecessary complexity.)

        "The historical reason was that in the very early days,
        we wanted to give people as few ways to argue that we were
        less secure than Bitcoin. So where there was no good reason
        to change something, it was not changed."
*/
AccountID
calcAccountID(PublicKey const& pk)
{
    static_assert(AccountID::num_bytes == sizeof(ripesha_hasher::result_type));

    ripesha_hasher rsh;
    rsh(pk.data(), pk.size());
    return AccountID{static_cast<ripesha_hasher::result_type>(rsh)};
}

AccountID const&
xrpAccount()
{
    static AccountID const account(zero);
    return account;
}

AccountID const&
noAccount()
{
    static AccountID const account(1);
    return account;
}

bool
to_issuer(AccountID& issuer, ustring_view s)
{
    if (issuer.parseHex(s))
        return true;
    auto const account = parseBase58<AccountID>(s);
    if (!account)
        return false;
    issuer = *account;
    return true;
}

#ifdef LATER
//------------------------------------------------------------------------------

/*  VFALCO NOTE
    An alternate implementation could use a pair of insert-only
    hash maps that each use a single large memory allocation
    to store a fixed size hash table and all of the AccountID/string
    pairs laid out in memory (wouldn't use std::string here just a
    length prefixed or zero terminated array). Possibly using
    boost::intrusive as the basis for the unordered container.
    This would cut down to one allocate/free cycle per swap of
    the map.
*/

AccountIDCache::AccountIDCache(std::size_t capacity) : capacity_(capacity)
{
    m1_.reserve(capacity_);
}

std::string
AccountIDCache::toBase58(AccountID const& id) const
{
    std::lock_guard lock(mutex_);
    auto iter = m1_.find(id);
    if (iter != m1_.end())
        return iter->second;
    iter = m0_.find(id);
    std::string result;
    if (iter != m0_.end())
    {
        result = iter->second;
        // Can use insert-only hash maps if
        // we didn't erase from here.
        m0_.erase(iter);
    }
    else
    {
        result = ripple::toBase58(id);
    }
    if (m1_.size() >= capacity_)
    {
        m0_ = std::move(m1_);
        m1_.clear();
        m1_.reserve(capacity_);
    }
    m1_.emplace(id, result);
    return result;
}
#endif

} // namespace xrpl

