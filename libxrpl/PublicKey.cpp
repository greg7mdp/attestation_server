#include "PublicKey.h"

namespace xrpl {

//  ---------------- PublicKey  ---------------------
std::optional<KeyType>
publicKeyType(ustring_view slice)
{
    if (slice.size() == 33)
    {
        if (slice[0] == 0xED)
            return KeyType::ed25519;

        if (slice[0] == 0x02 || slice[0] == 0x03)
            return KeyType::secp256k1;
    }

    return std::nullopt;
}

} // namespace xrpl
