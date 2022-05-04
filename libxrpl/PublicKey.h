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
    

} // namespace xrpl


#endif // LIBXRPL_PUBLICKEY_H_INCLUDED
