#ifndef LIBXRPL_BASE58_H_INCLUDED
#define LIBXRPL_BASE58_H_INCLUDED

#include "Common.h"

namespace xrpl {

    enum class TokenType : std::uint8_t {
        None            = 1,   // unused
        NodePublic      = 28,
        NodePrivate     = 32,
        AccountID       = 0,
        AccountPublic   = 35,
        AccountSecret   = 34,
        FamilyGenerator = 41,  // unused
        FamilySeed      = 33
    };

    template <class T>
    std::optional<T> parseBase58(ustring_view  s);

    template <class T>
    std::optional<T> parseBase58(TokenType type, ustring_view s);

    // Encode data in Base58Check format using XRPL alphabet
    //  For details on the format see
    //  https://xrpl.org/base58-encodings.html#base58-encodings
    std::string encodeBase58Token(TokenType type, ustring_view data);

    // Decode a token of given type encoded using Base58Check and the XRPL alphabet
    std::string decodeBase58Token(ustring_view s, TokenType type);
}


#endif // LIBXRPL_BASE58_H_INCLUDED
