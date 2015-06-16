// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 Bitcoin Developers
// Copyright (c) 2014 Talkcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NIST5_HASH_H
#define TALKCOIN_HASH_H

#include "uint256.h"

#include "deps/sph_blake.h"
#include "deps/sph_groestl.h"
#include "deps/sph_jh.h"
#include "deps/sph_keccak.h"
#include "deps/sph_skein.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>

#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_blake512_context     z_blake;
GLOBAL sph_groestl512_context   z_groestl;
GLOBAL sph_jh512_context        z_jh;
GLOBAL sph_keccak512_context    z_keccak;
GLOBAL sph_skein512_context     z_skein;

#define fillz_nist5() do { \
    sph_blake512_init(&z_blake); \
    sph_groestl512_init(&z_groestl); \
    sph_jh512_init(&z_jh); \
    sph_keccak512_init(&z_keccak); \
    sph_skein512_init(&z_skein); \
} while (0) 

#define ZBLAKE (memcpy(&ctx_blake, &z_blake, sizeof(z_blake)))
#define ZGROESTL (memcpy(&ctx_groestl, &z_groestl, sizeof(z_groestl)))
#define ZJH (memcpy(&ctx_jh, &z_jh, sizeof(z_jh)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZSKEIN (memcpy(&ctx_skein, &z_skein, sizeof(z_skein)))

template<typename T1>
inline uint256 NIST5Hash(const T1 pbegin, const T1 pend)
{
    sph_blake512_context     ctx_blake;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

    static unsigned char pblank[1];
    uint512 hash;

    // Blake512
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, (pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]));
    sph_blake512_close(&ctx_blake, (unsigned char*)&hash);
    // Groestl512
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, (unsigned char*)&hash, sizeof(hash));
    sph_groestl512_close(&ctx_groestl, (unsigned char*)&hash);
    // Jh512
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, (unsigned char*)&hash, sizeof(hash));
    sph_jh512_close(&ctx_jh, (unsigned char*)&hash);
    // Keccak512
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, (unsigned char*)&hash, sizeof(hash));
    sph_keccak512_close(&ctx_keccak, (unsigned char*)&hash);
    // Skein512
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, (unsigned char*)&hash, sizeof(hash));
    sph_skein512_close(&ctx_skein, (unsigned char*)&hash);

    //printf("\nhash: %s\n", hash.ToString().c_str());

    return hash.trim256();
}

#endif // HASHBLOCK_H
