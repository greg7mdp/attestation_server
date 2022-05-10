#include "Base58.h"
#include <boost/container/small_vector.hpp>
#include "Digest.h"

#include <cstring>
#include <memory>
#include <type_traits>

namespace xrpl {

static constexpr char const* alphabetForward = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

static constexpr std::array<int, 256> const alphabetReverse = []() {
    std::array<int, 256> map{};
    for (auto& m : map)
        m = -1;
    for (int i = 0, j = 0; alphabetForward[i] != 0; ++i)
        map[static_cast<unsigned char>(alphabetForward[i])] = j++;
    return map;
}();

template <class Hasher>
static typename Hasher::result_type digest(void const* data, std::size_t size) noexcept
{
    Hasher h;
    h(data, size);
    return static_cast<typename Hasher::result_type>(h);
}

template <class Hasher, class T, std::size_t N, class = std::enable_if_t<sizeof(T) == 1>>
static typename Hasher::result_type digest(std::array<T, N> const& v)
{
    return digest<Hasher>(v.data(), v.size());
}

// Computes a double digest (e.g. digest of the digest)
template <class Hasher, class... Args>
static typename Hasher::result_type digest2(Args const&... args)
{
    return digest<Hasher>(digest<Hasher>(args...));
}

/** Calculate a 4-byte checksum of the data

    The checksum is calculated as the first 4 bytes
    of the SHA256 digest of the message. This is added
    to the base58 encoding of identifiers to detect
    user error in data entry.

    @note This checksum algorithm is part of the client API
*/
static void checksum(void* out, void const* message, std::size_t size)
{
    auto const h = digest2<sha256_hasher>(message, size);
    std::memcpy(out, h.data(), 4);
}

namespace detail {

/* The base58 encoding & decoding routines in this namespace are taken from
 * Bitcoin but have been modified from the original.
 *
 * Copyright (c) 2014 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
static ustring encodeBase58(void const* message, std::size_t size, void* temp, std::size_t temp_size)
{
    auto pbegin = reinterpret_cast<unsigned char const*>(message);
    auto const pend = pbegin + size;

    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0)
    {
        pbegin++;
        zeroes++;
    }

    auto const b58begin = reinterpret_cast<unsigned char*>(temp);
    auto const b58end = b58begin + temp_size;

    std::fill(b58begin, b58end, 0);

    while (pbegin != pend)
    {
        int carry = *pbegin;
        // Apply "b58 = b58 * 256 + ch".
        for (auto iter = b58end; iter != b58begin; --iter)
        {
            carry += 256 * (iter[-1]);
            iter[-1] = carry % 58;
            carry /= 58;
        }
        assert(carry == 0);
        pbegin++;
    }

    // Skip leading zeroes in base58 result.
    auto iter = b58begin;
    while (iter != b58end && *iter == 0)
        ++iter;

    // Translate the result into a string.
    ustring str;
    str.reserve(zeroes + (b58end - iter));
    str.assign(zeroes, alphabetForward[0]);
    while (iter != b58end)
        str += alphabetForward[*(iter++)];
    return str;
}

static ustring decodeBase58(ustring_view sv)
{
    auto psz = sv.data();
    auto remain = sv.size();
    // Skip and count leading zeroes
    int zeroes = 0;
    while (remain > 0 && alphabetReverse[*psz] == 0)
    {
        ++zeroes;
        ++psz;
        --remain;
    }

    if (remain > 64)
        return {};

    // Allocate enough space in big-endian base256 representation.
    // log(58) / log(256), rounded up.
    std::vector<unsigned char> b256(remain * 733 / 1000 + 1);
    while (remain > 0)
    {
        auto carry = alphabetReverse[*psz];
        if (carry == -1)
            return {};
        // Apply "b256 = b256 * 58 + carry".
        for (auto iter = b256.rbegin(); iter != b256.rend(); ++iter)
        {
            carry += 58 * *iter;
            *iter = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        ++psz;
        --remain;
    }
    // Skip leading zeroes in b256.
    auto iter = std::find_if(b256.begin(), b256.end(), [](unsigned char c) { return c != 0; });
    ustring result;
    result.reserve(zeroes + (b256.end() - iter));
    result.assign(zeroes, 0x00);
    while (iter != b256.end())
        result.push_back(*(iter++));
    return result;
}

}  // namespace detail

ustring encodeBase58Token(TokenType type, ustring_view sv)
{
    std::size_t size = sv.size();

    // expanded token includes type + 4 byte checksum
    auto const expanded = 1 + size + 4;

    // We need expanded + expanded * (log(256) / log(58)) which is
    // bounded by expanded + expanded * (138 / 100 + 1) which works
    // out to expanded * 3:
    auto const bufsize = expanded * 3;

    boost::container::small_vector<std::uint8_t, 1024> buf(bufsize);

    // Lay the data out as
    //      <type><token><checksum>
    buf[0] = safe_cast<std::underlying_type_t<TokenType>>(type);
    if (size)
        std::memcpy(buf.data() + 1, sv.data(), size);
    checksum(buf.data() + 1 + size, buf.data(), 1 + size);

    return detail::encodeBase58(buf.data(), expanded, buf.data() + expanded, bufsize - expanded);
}

ustring decodeBase58Token(ustring_view sv, TokenType type)
{
    ustring const ret = detail::decodeBase58(sv);

    // Reject zero length tokens
    if (ret.size() < 6)
        return {};

    // The type must match.
    if (type != safe_cast<TokenType>(ret[0]))
        return {};

    // And the checksum must as well.
    std::array<std::uint8_t, 4> guard;
    checksum(guard.data(), ret.data(), ret.size() - guard.size());
    if (!std::equal(guard.rbegin(), guard.rend(), ret.rbegin()))
        return {};

    // Skip the leading type byte and the trailing checksum151.
    return ret.substr(1, ret.size() - 1 - guard.size());
}

}  // namespace xrpl
