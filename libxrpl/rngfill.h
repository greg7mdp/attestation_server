#ifndef BEAST_RANDOM_RNGFILL_H_INCLUDED
#define BEAST_RANDOM_RNGFILL_H_INCLUDED

#include <array>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace beast {

template <class Generator>
void rngfill(void* buffer, std::size_t bytes, Generator& g)
{
    while (bytes > 0)
    {
        auto const v = g();
        auto dest_size = std::min(bytes, sizeof(v));
        std::memcpy(buffer, &v, dest_size);
        buffer = reinterpret_cast<std::uint8_t*>(buffer) + sizeof(v);
        bytes -= std::min(bytes, dest_size);
    }
}

template <class Generator, std::size_t N, class = std::enable_if_t<N % sizeof(typename Generator::result_type) == 0>>
void rngfill(std::array<std::uint8_t, N>& a, Generator& g)
{
    using result_type = typename Generator::result_type;
    auto i = N / sizeof(result_type);
    result_type* p = reinterpret_cast<result_type*>(a.data());
    while (i--)
        *p++ = g();
}

}  // namespace beast

#endif
