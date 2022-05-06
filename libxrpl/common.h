#ifndef LIBXRPL_COMMON_H_INCLUDED
#define LIBXRPL_COMMON_H_INCLUDED

#include <cassert>
#include <cstdint>
#include <string>
#include <cstring>
#include <string_view>
#include <array>
#include <vector>
#include <optional>
#include <algorithm>
#ifndef _MSC_VER
    #include <cxxabi.h>
#endif

#include "libxrpl_export.h"
#include <boost/endian/conversion.hpp>

namespace xrpl {

    // ----------------------------- ustring -------------------------------------------
    using ustring      = std::basic_string<std::uint8_t>;
    using ustring_view = std::basic_string_view<std::uint8_t>;

    template <class T, std::size_t N>
    std::enable_if_t<
    std::is_same<T, char>::value || std::is_same<T, unsigned char>::value, ustring_view>
    static inline to_ustring_view(std::array<T, N> const& a)
    {
        return ustring_view(a.data(), a.size());
    }

    template <class T, class Alloc>
    std::enable_if_t<
        std::is_same<T, char>::value || std::is_same<T, unsigned char>::value, ustring_view>
    static inline to_ustring_view(std::vector<T, Alloc> const& v)
    {
        return ustring_view(v.data(), v.size());
    }

    static inline ustring_view to_ustring_view(char const *s)
    {
        return ustring_view(reinterpret_cast<std::uint8_t const *>(s), strlen(s));
    }
    
    // ----------------------------- zero ---------------------------------------
    struct Zero
    {
        explicit Zero() = default;
    };

    namespace {
        static constexpr Zero zero{};
    }

    
    // ----------------------------- is_contiguous_container ------------
    namespace detail {

        template <class Container, class = std::void_t<>>
        struct is_contiguous_container : std::false_type
        {
        };

        template <class Container>
        struct is_contiguous_container<
            Container,
            std::void_t<
                decltype(std::declval<Container const>().size()),
                decltype(std::declval<Container const>().data()),
                typename Container::value_type>> : std::true_type
        {
    };

    }  // namespace detail
    
    // ----------------------------- uint256 -------------------------------
    template <std::size_t num_bits, class Tag = void>
    class  base_uint
    {
    public:
        static constexpr std::size_t num_words = num_bits / sizeof(std::uint32_t);
        static constexpr std::size_t num_bytes = num_bits / 8;

        using value_type = std::uint8_t;
        using pointer = value_type*;
        using reference = value_type&;
        using const_pointer = value_type const*;
        using const_reference = value_type const&;

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
        
        static base_uint
        fromVoid(void const* data)
        {
            base_uint res;
            memcpy(res.data_.data(), data, num_bytes);
            return res;
        }

    private:
        static_assert((num_bits % 32) == 0,
                      "The length of a base_uint in bits must be a multiple of 32.");

        static_assert(num_bits >= 64,
                      "The length of a base_uint in bits must be at least 64.");
        
        // This is really big-endian in byte order.
        // We sometimes use std::uint32_t for speed.
        std::array<std::uint32_t, num_words> data_;

        // Helper function to initialize a base_uint from a std::string_view.
        enum class ParseResult {
            okay,
            badLength,
            badChar,
        };
        
        constexpr std::optional<decltype(data_)>
        parseFromStringView(ustring_view sv) noexcept
        {
            // Local lambda that converts a single hex char to four bits and
            // ORs those bits into a uint32_t.
            auto hexCharToUInt = [](char c,
                                    std::uint32_t shift,
                                    std::uint32_t& accum) -> ParseResult {
                std::uint32_t nibble = 0xFFu;
                if (c < '0' || c > 'f')
                    return ParseResult::badChar;

                if (c >= 'a')
                    nibble = static_cast<std::uint32_t>(c - 'a' + 0xA);
                else if (c >= 'A')
                    nibble = static_cast<std::uint32_t>(c - 'A' + 0xA);
                else if (c <= '9')
                    nibble = static_cast<std::uint32_t>(c - '0');

                if (nibble > 0xFu)
                    return ParseResult::badChar;

                accum |= (nibble << shift);

                return ParseResult::okay;
            };

            decltype(data_) ret{};

            if (sv == reinterpret_cast<std::uint8_t const *>("0"))
            {
                return { ret };
            }

            if (sv.size() != size() * 2)
                return {};

            std::size_t i = 0u;
            auto in = sv.begin();
            while (in != sv.end())
            {
                std::uint32_t accum = {};
                for (std::uint32_t shift : {4u, 0u, 12u, 8u, 20u, 16u, 28u, 24u})
                {
                    if (auto const result = hexCharToUInt(*in++, shift, accum);
                        result != ParseResult::okay)
                        return {};
                }
                ret[i++] = accum;
            }
            return { ret };
        }

    public:
        constexpr base_uint() : data_{}
        {
        }
        
        base_uint(ustring_view sv) {
            memcpy(data_.data(), sv.data(), num_bytes);
        }

        constexpr base_uint(Zero) : data_{}
        {
        }

        explicit base_uint(std::uint64_t b)
        {
            *this = b;
        }

        template <
            class Container,
            class = std::enable_if_t<
                detail::is_contiguous_container<Container>::value &&
                std::is_trivially_copyable<typename Container::value_type>::value>>
        explicit base_uint(Container const& c)
        {
            assert(c.size() * sizeof(typename Container::value_type) == size());
            std::memcpy(data_.data(), c.data(), size());
        }

        bool
        operator!() const
        {
            return *this == zero;
        }

        const base_uint
        operator~() const
        {
            base_uint ret;

            for (std::size_t i = 0; i < num_words; i++)
                ret.data_[i] = ~data_[i];

            return ret;
        }


        base_uint&
        operator=(std::uint64_t uHost)
        {
            *this = zero;
            union
            {
                unsigned u[2];
                std::uint64_t ul;
            };
            // Put in least significant bits.
            ul = boost::endian::native_to_big(uHost);
            data_[num_words - 2] = u[0];
            data_[num_words - 1] = u[1];
            return *this;
        }
        [[nodiscard]] constexpr bool
        parseHex(ustring_view sv)
        {
            auto const result = parseFromStringView(sv);
            if (!result)
                return false;

            data_ = *result;
            return true;
        }
    };

    template <std::size_t Bits, class Tag>
    inline int
    compare(base_uint<Bits, Tag> const& a, base_uint<Bits, Tag> const& b)
    {
        auto av = a.view();
        auto ret = std::mismatch(av.cbegin(), av.cend(), b.view().cbegin());
        
        if (ret.first == av.cend())
            return 0;
        
        // a > b
        if (*ret.first > *ret.second)
            return 1;
        
        // a < b
        return -1;
    }
    
    template <std::size_t Bits, class Tag>
    inline bool
    operator==(base_uint<Bits, Tag> const& a, base_uint<Bits, Tag> const& b)
    {
        return compare(a, b) == 0;
    }

    using uint128 = base_uint<128>;
    using uint160 = base_uint<160>;
    using uint256 = base_uint<256>;

    // ----------------------------- NodeID / Currency -----------------------------------
    namespace detail {

        struct CurrencyTag
        {
            explicit CurrencyTag() = default;
        };

        struct DirectoryTag
        {
            explicit DirectoryTag() = default;
        };

        struct NodeIDTag
        {
            explicit NodeIDTag() = default;
        };

    }  // namespace detail

    /** Directory is an index into the directory of offer books.
        The last 64 bits of this are the quality. */
    using Directory = base_uint<256, detail::DirectoryTag>;

    /** Currency is a hash representing a specific currency. */
    using Currency = base_uint<160, detail::CurrencyTag>;

    /** NodeID is a 160-bit hash representing one node. */
    using NodeID = base_uint<160, detail::NodeIDTag>;

    /** XRP currency. */
    static inline Currency const& xrpCurrency() 
    {
        static Currency const currency(zero);
        return currency;
    }

    /** A placeholder for empty currencies. */
    static inline Currency const&
    noCurrency()
    {
        static Currency const currency(1);
        return currency;
    }

    /** We deliberately disallow the currency that looks like "XRP" because too
        many people were using it instead of the correct XRP currency. */
    static inline Currency const&
    badCurrency() 
    {
        static Currency const currency(0x5852500000000000);
        return currency;
    }
#if 0
    inline bool
    isXRP(Currency const& c)
    {
        return c == zero;
    }
#endif

    
    // ----------------------------- AccountID ---------------------------------------
    namespace detail {
        struct AccountIDTag
        {
            explicit AccountIDTag() = default;
        };
        
    }  // namespace detail
    
    /** A 160-bit unsigned that uniquely identifies an account. */
    using AccountID = base_uint<160, detail::AccountIDTag>;
    
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
