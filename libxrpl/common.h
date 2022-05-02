#ifndef LIBXRPL_COMMON_H_INCLUDED
#define LIBXRPL_COMMON_H_INCLUDED

#include <cstdint>
#include <string>
#include <string_view>

#include "libxrpl_export.h"

namespace xrpl {
    
    using PublicKey = std::string;
    using SecretKey = std::string;

    struct Port
    {
        enum class Protocol { http, ws, peer };
        
        Protocol protocol;
        size_t port_nb;
        // ? ip;
        // ? admin;
    };
        

}

#endif // LIBXRPL_COMMON_H_INCLUDED
