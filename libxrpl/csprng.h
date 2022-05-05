#ifndef LIBXRPL_CSPRNG_H_INCLUDED
#define LIBXRPL_CSPRNG_H_INCLUDED

#include <mutex>
#include <random>
#include <openssl/rand.h>

//---------------------------------------------------------------------------------
namespace xrpl {
    
class csprng_engine
{
private:
    std::mutex mutex_;

    void
    mix(void* data, std::size_t size, double bitsPerByte)
    {
        assert(data != nullptr);
        assert(size != 0);
        assert(bitsPerByte != 0);

        std::lock_guard lock(mutex_);
        RAND_add(data, size, (size * bitsPerByte) / 8.0);
    }

public:
    using result_type = std::uint64_t;

    csprng_engine(csprng_engine const&) = delete;
    csprng_engine& operator=(csprng_engine const&) = delete;

    csprng_engine(csprng_engine&&) = delete;
    csprng_engine& operator=(csprng_engine&&) = delete;

    csprng_engine()
    {
        mix_entropy();
    }
    
    /** Mix entropy into the pool */
    void
    mix_entropy(void* buffer = nullptr, std::size_t count = 0)
    {
        std::array<std::random_device::result_type, 128> entropy;

        {
            // On every platform we support, std::random_device
            // is non-deterministic and should provide some good
            // quality entropy.
            std::random_device rd;

            for (auto& e : entropy)
                e = rd();
        }

        // Assume 2 bits per byte for the system entropy:
        mix(entropy.data(),
            entropy.size() * sizeof(std::random_device::result_type),
            2.0);

        // We want to be extremely conservative about estimating
        // how much entropy the buffer the user gives us contains
        // and assume only 0.5 bits of entropy per byte:
        if (buffer != nullptr && count != 0)
            mix(buffer, count, 0.5);
    }

    /** Generate a random integer */
    result_type
    operator()()
    {
        result_type ret;

        std::lock_guard lock(mutex_);

        auto const result =
            RAND_bytes(reinterpret_cast<unsigned char*>(&ret), sizeof(ret));

        if (result == 0)
            Throw<std::runtime_error>("Insufficient entropy");

        return ret;
    }

    /** Fill a buffer with the requested amount of random data */
    void
    operator()(void* ptr, std::size_t count)
    {
        std::lock_guard lock(mutex_);

        auto const result =
            RAND_bytes(reinterpret_cast<unsigned char*>(ptr), count);

        if (result != 1)
            Throw<std::runtime_error>("Insufficient entropy");
    }

    /* The smallest possible value that can be returned */
    static constexpr result_type
    min()
    {
        return std::numeric_limits<result_type>::min();
    }

    /* The largest possible value that can be returned */
    static constexpr result_type
    max()
    {
        return std::numeric_limits<result_type>::max();
    }
};

/** The default cryptographically secure PRNG

    Use this when you need to generate random numbers or
    data that will be used for encryption or passed into
    cryptographic routines.

    This meets the requirements of UniformRandomNumberEngine
*/
inline csprng_engine& crypto_prng()
{
    static csprng_engine engine;
    return engine;
}
    
} // namespace xrpl

#endif
