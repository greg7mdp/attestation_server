#ifndef LIBXRPL_COMMON_H_INCLUDED
#define LIBXRPL_COMMON_H_INCLUDED

#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <array>
#include <vector>
#include <optional>
#ifndef _MSC_VER
    #include <cxxabi.h>
#endif

#include "libxrpl_export.h"

namespace xrpl {

    // ----------------------------- ustring -------------------------------------------
    using ustring      = std::basic_string<std::uint8_t>;
    using ustring_view = std::basic_string_view<std::uint8_t>;
    
    // ----------------------------- uint256 -------------------------------------------
    template <std::size_t num_bits, class Tag = void>
    class base_uint
    {
    public:
        static constexpr std::size_t num_words = num_bits / sizeof(std::uint32_t);
        static constexpr std::size_t num_bytes = num_bits / 8;

#if 1
        ustring_view view() const
        {
            return { reinterpret_cast<std::uint8_t const *>(data_.data()), size() };
        }

        std::uint8_t *data()
        {
            return reinterpret_cast<std::uint8_t *>(data_.data());
        }

        std::uint8_t const *data() const
        {
            return reinterpret_cast<std::uint8_t const *>(data_.data());
        }

        static constexpr std::size_t size()
        {
            return num_bytes;
        }
#else
        using value_type = unsigned char;
        using pointer = value_type*;
        using reference = value_type&;
        using const_pointer = value_type const*;
        using const_reference = value_type const&;
        
        pointer data()
        {
            return reinterpret_cast<pointer>(data_.data());
        }
        
        const_pointer data() const
        {
            return reinterpret_cast<const_pointer>(data_.data());
        }
#endif
        
    private:
        static_assert((num_bits % 32) == 0,
                      "The length of a base_uint in bits must be a multiple of 32.");

        static_assert(num_bits >= 64,
                      "The length of a base_uint in bits must be at least 64.");
        
        // This is really big-endian in byte order.
        // We sometimes use std::uint32_t for speed.
        std::array<std::uint32_t, num_words> data_;

    public:
        base_uint(ustring_view sv) {
            memcpy(data_.data(), sv.data(), num_bytes);
        }

    };

    using uint128 = base_uint<128>;
    using uint160 = base_uint<160>;
    using uint256 = base_uint<256>;

    // ----------------------------- type_name ---------------------------------------
    template <typename T>
    std::string type_name()
    {
        using TR = typename std::remove_reference<T>::type;

        std::string name = typeid(TR).name();

#ifndef _MSC_VER
        if (auto s = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, nullptr))
        {
            name = s;
            std::free(s);
        }
#endif

        if (std::is_const<TR>::value)
            name += " const";
        if (std::is_volatile<TR>::value)
            name += " volatile";
        if (std::is_lvalue_reference<T>::value)
            name += "&";
        else if (std::is_rvalue_reference<T>::value)
            name += "&&";

        return name;
    }
    
    // ----------------------------- LogThrow / Throw / LogicError ------------------
    /** Generates and logs a call stack */
    void
    LogThrow(std::string const& title);

    /** Rethrow the exception currently being handled.

        When called from within a catch block, it will pass
        control to the next matching exception handler, if any.
        Otherwise, std::terminate will be called.
    */
    [[noreturn]] inline void
    Rethrow()
    {
        LogThrow("Re-throwing exception");
        throw;
    }

    template <class E, class... Args>
    [[noreturn]] inline void
    Throw(Args&&... args)
    {
        static_assert(
            std::is_convertible<E*, std::exception*>::value,
            "Exception must derive from std::exception.");

        E e(std::forward<Args>(args)...);
        LogThrow(
            std::string(
                "Throwing exception of type " + type_name<E>() + ": ") +
            e.what());
        throw e;
    }

    /** Called when faulty logic causes a broken invariant. */
    [[noreturn]] void
    LogicError(std::string const& how) noexcept;    


    // ----------------------------- PublicKey ----------------------------------------
    using PublicKey = ustring;

    // ----------------------------- Port ---------------------------------------------
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
