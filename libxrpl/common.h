#ifndef LIBXRPL_COMMON_H_INCLUDED
#define LIBXRPL_COMMON_H_INCLUDED

#include <cstdint>
#include <string>
#include <string_view>
#include <array>
#include <vector>
#include <optional>

#include "libxrpl_export.h"

using ustring_view = std::basic_string_view<std::uint8_t>;

template <std::size_t num_bits, class Tag = void>
class base_uint
{
    static_assert((num_bits % 32) == 0,
        "The length of a base_uint in bits must be a multiple of 32.");

    static_assert(num_bits >= 64,
        "The length of a base_uint in bits must be at least 64.");

    static constexpr std::size_t num_words = num_bits / 32;

    // This is really big-endian in byte order.
    // We sometimes use std::uint32_t for speed.
    std::array<std::uint32_t, num_words> data_;
};

using uint128 = base_uint<128>;
using uint160 = base_uint<160>;
using uint256 = base_uint<256>;


namespace xrpl {
        
    using PublicKey = std::string;

    struct Port
    {
        enum class Protocol { http, ws, peer };
        
        Protocol protocol;
        size_t port_nb;
        // ? ip;
        // ? admin;
    };

    void secure_erase(void* dest, std::size_t bytes);
    
} // namespace xrpl


#endif // LIBXRPL_COMMON_H_INCLUDED
