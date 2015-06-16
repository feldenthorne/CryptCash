// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef HASHBLOCK_WHIRLPOOL_H
#define HASHBLOCK_WHIRLPOOL_H

#include "uint256.h"
#include "deps/sph_whirlpool.h"

#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_whirlpool1_context     z_whirlpool1;

#define fillz_whirlpool() do { \
    sph_whirlpool1_init(&z_whirlpool1); \
} while (0) 

#define ZWHIRLPOOL1 (memcpy(&ctx_whirlpool1, &z_whirlpool1, sizeof(z_whirlpool1)))

template<typename T1>
inline uint256 Whirlpool(const T1 pbegin, const T1 pend)
{
    sph_whirlpool1_context whirlpool;
    static unsigned char pblank[1];
    uint512 hash[4];

    sph_whirlpool1_init(&whirlpool);
    sph_whirlpool1 (&whirlpool, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_whirlpool1_close(&whirlpool, static_cast<void*>(&hash[0]));

	sph_whirlpool1_init(&whirlpool);
	sph_whirlpool1(&whirlpool,static_cast<const void*>(&hash[0]),64);
	sph_whirlpool1_close(&whirlpool,static_cast<void*>(&hash[1]));

	sph_whirlpool1_init(&whirlpool);
	sph_whirlpool1(&whirlpool,static_cast<const void*>(&hash[1]),64);
	sph_whirlpool1_close(&whirlpool,static_cast<void*>(&hash[2]));

	sph_whirlpool1_init(&whirlpool);
	sph_whirlpool1(&whirlpool,static_cast<const void*>(&hash[2]),64);
	sph_whirlpool1_close(&whirlpool,static_cast<void*>(&hash[3]));

    return hash[3].trim256();
}

#endif
