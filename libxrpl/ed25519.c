#include "stdlib.h"
#include "assert.h"

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

extern void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk)
{
    assert(0);
    abort();
}

extern void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk,
                         const ed25519_public_key pk, ed25519_signature RS)
{
    assert(0);
    abort();
}
 
