#include <cstdint>
#include <string>

#include "libxrpl_export.h"

namespace lib1 {
class LIBXRPL_EXPORT hello
{
public:
    [[nodiscard]] int32_t
    saySomething(const std::string& something) const noexcept;
#ifdef WITH_OPENSSL
    [[nodiscard]] int32_t
    saySomethingHashed(const std::string& something) const noexcept;
#endif
};
}  // namespace lib1
