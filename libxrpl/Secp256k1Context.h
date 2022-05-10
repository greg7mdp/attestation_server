#ifndef LIBXRPL_SECP256K1CONTEXT_H_INCLUDED
#define LIBXRPL_SECP256K1CONTEXT_H_INCLUDED

#include <secp256k1.h>

//---------------------------------------------------------------------------------
namespace xrpl {

template <class = void>
secp256k1_context const* secp256k1Context()
{
    struct holder
    {
        secp256k1_context* impl;
        holder() : impl(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
        {
        }

        ~holder()
        {
            secp256k1_context_destroy(impl);
        }
    };
    static holder const h;
    return h.impl;
}

}  // namespace xrpl

#endif
