/* $Id: haval.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * HAVAL implementation.
 *
 * The HAVAL reference paper is of questionable clarity with regards to
 * some details such as endianness of bits within a byte, bytes within
 * a 32-bit word, or the actual ordering of words within a stream of
 * words. This implementation has been made compatible with the reference
 * implementation available on: http://labs.calyptix.com/haval.php
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>

#include "sph_haval.h"

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_HAVAL
#define SPH_SMALL_FOOTPRINT_HAVAL   1
#endif

/*
 * Initialize a context. "olen" is the output length, in 32-bit words
 * (between 4 and 8, inclusive). "passes" is the number of passes
 * (3, 4 or 5).
 */
static void
haval_init(sph_haval_context *sc, unsigned olen, unsigned passes)
{
	sc->s0 = SPH_C32(0x243F6A88);
	sc->s1 = SPH_C32(0x85A308D3);
	sc->s2 = SPH_C32(0x13198A2E);
	sc->s3 = SPH_C32(0x03707344);
	sc->s4 = SPH_C32(0xA4093822);
	sc->s5 = SPH_C32(0x299F31D0);
	sc->s6 = SPH_C32(0x082EFA98);
	sc->s7 = SPH_C32(0xEC4E6C89);
	sc->olen = olen;
	sc->passes = passes;
#if SPH_64
	sc->count = 0;
#else
	sc->count_high = 0;
	sc->count_low = 0;
#endif
}

/*
 * Mixing operation used for 128-bit output tailoring. This function
 * takes the byte 0 from a0, byte 1 from a1, byte 2 from a2 and byte 3
 * from a3, and combines them into a 32-bit word, which is then rotated
 * to the left by n bits.
 */
static SPH_INLINE sph_u32
mix128(sph_u32 a0, sph_u32 a1, sph_u32 a2, sph_u32 a3, int n)
{
	sph_u32 tmp;

	tmp = (a0 & SPH_C32(0x000000FF))
		| (a1 & SPH_C32(0x0000FF00))
		| (a2 & SPH_C32(0x00FF0000))
		| (a3 & SPH_C32(0xFF000000));
	if (n > 0)
		tmp = SPH_ROTL32(tmp, n);
	return tmp;
}

/*
 * Mixing operation used to compute output word 0 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_0(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x01F80000))
		| (x6 & SPH_C32(0xFE000000))
		| (x7 & SPH_C32(0x0000003F));
	return SPH_ROTL32(tmp, 13);
}

/*
 * Mixing operation used to compute output word 1 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_1(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0xFE000000))
		| (x6 & SPH_C32(0x0000003F))
		| (x7 & SPH_C32(0x00000FC0));
	return SPH_ROTL32(tmp, 7);
}

/*
 * Mixing operation used to compute output word 2 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_2(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x0000003F))
		| (x6 & SPH_C32(0x00000FC0))
		| (x7 & SPH_C32(0x0007F000));
	return tmp;
}

/*
 * Mixing operation used to compute output word 3 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_3(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x00000FC0))
		| (x6 & SPH_C32(0x0007F000))
		| (x7 & SPH_C32(0x01F80000));
	return tmp >> 6;
}

/*
 * Mixing operation used to compute output word 4 for 160-bit output.
 */
static SPH_INLINE sph_u32
mix160_4(sph_u32 x5, sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x5 & SPH_C32(0x0007F000))
		| (x6 & SPH_C32(0x01F80000))
		| (x7 & SPH_C32(0xFE000000));
	return tmp >> 12;
}

/*
 * Mixing operation used to compute output word 0 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_0(sph_u32 x6, sph_u32 x7)
{
	sph_u32 tmp;

	tmp = (x6 & SPH_C32(0xFC000000)) | (x7 & SPH_C32(0x0000001F));
	return SPH_ROTL32(tmp, 6);
}

/*
 * Mixing operation used to compute output word 1 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_1(sph_u32 x6, sph_u32 x7)
{
	return (x6 & SPH_C32(0x0000001F)) | (x7 & SPH_C32(0x000003E0));
}

/*
 * Mixing operation used to compute output word 2 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_2(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x000003E0)) | (x7 & SPH_C32(0x0000FC00))) >> 5;
}

/*
 * Mixing operation used to compute output word 3 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_3(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x0000FC00)) | (x7 & SPH_C32(0x001F0000))) >> 10;
}

/*
 * Mixing operation used to compute output word 4 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_4(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x001F0000)) | (x7 & SPH_C32(0x03E00000))) >> 16;
}

/*
 * Mixing operation used to compute output word 5 for 192-bit output.
 */
static SPH_INLINE sph_u32
mix192_5(sph_u32 x6, sph_u32 x7)
{
	return ((x6 & SPH_C32(0x03E00000)) | (x7 & SPH_C32(0xFC000000))) >> 21;
}

/*
 * Write out HAVAL output. The output length is tailored to the requested
 * length.
 */
static void
haval_out(sph_haval_context *sc, void *dst)
{
	DSTATE;
	unsigned char *buf;

	buf = (unsigned char*)dst;
	RSTATE;
	switch (sc->olen) {
	case 4:
		sph_enc32le(buf,      SPH_T32(s0 + mix128(s7, s4, s5, s6, 24)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + mix128(s6, s7, s4, s5, 16)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + mix128(s5, s6, s7, s4, 8)));
		sph_enc32le(buf + 12, SPH_T32(s3 + mix128(s4, s5, s6, s7, 0)));
		break;
	case 5:
		sph_enc32le(buf,      SPH_T32(s0 + mix160_0(s5, s6, s7)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + mix160_1(s5, s6, s7)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + mix160_2(s5, s6, s7)));
		sph_enc32le(buf + 12, SPH_T32(s3 + mix160_3(s5, s6, s7)));
		sph_enc32le(buf + 16, SPH_T32(s4 + mix160_4(s5, s6, s7)));
		break;
	case 6:
		sph_enc32le(buf,      SPH_T32(s0 + mix192_0(s6, s7)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + mix192_1(s6, s7)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + mix192_2(s6, s7)));
		sph_enc32le(buf + 12, SPH_T32(s3 + mix192_3(s6, s7)));
		sph_enc32le(buf + 16, SPH_T32(s4 + mix192_4(s6, s7)));
		sph_enc32le(buf + 20, SPH_T32(s5 + mix192_5(s6, s7)));
		break;
	case 7:
		sph_enc32le(buf,      SPH_T32(s0 + ((s7 >> 27) & 0x1F)));
		sph_enc32le(buf + 4,  SPH_T32(s1 + ((s7 >> 22) & 0x1F)));
		sph_enc32le(buf + 8,  SPH_T32(s2 + ((s7 >> 18) & 0x0F)));
		sph_enc32le(buf + 12, SPH_T32(s3 + ((s7 >> 13) & 0x1F)));
		sph_enc32le(buf + 16, SPH_T32(s4 + ((s7 >>  9) & 0x0F)));
		sph_enc32le(buf + 20, SPH_T32(s5 + ((s7 >>  4) & 0x1F)));
		sph_enc32le(buf + 24, SPH_T32(s6 + ((s7      ) & 0x0F)));
		break;
	case 8:
		sph_enc32le(buf,      s0);
		sph_enc32le(buf + 4,  s1);
		sph_enc32le(buf + 8,  s2);
		sph_enc32le(buf + 12, s3);
		sph_enc32le(buf + 16, s4);
		sph_enc32le(buf + 20, s5);
		sph_enc32le(buf + 24, s6);
		sph_enc32le(buf + 28, s7);
		break;
	}
}

/*
 * The main core functions inline the code with the COREx() macros. We
 * use a helper file, included three times, which avoids code copying.
 */

#undef PASSES
#define PASSES   3
#include "haval_helper.c"

#undef PASSES
#define PASSES   4
#include "haval_helper.c"

#undef PASSES
#define PASSES   5
#include "haval_helper.c"

/* ====================================================================== */

#define API(xxx, y) \
void \
sph_haval ## xxx ## _ ## y ## _init(void *cc) \
{ \
	haval_init((sph_haval_context*)cc, xxx >> 5, y); \
} \
 \
void \
sph_haval ## xxx ## _ ## y (void *cc, const void *data, size_t len) \
{ \
	haval ## y((sph_haval_context*)cc, data, len); \
} \
 \
void \
sph_haval ## xxx ## _ ## y ## _close(void *cc, void *dst) \
{ \
	haval ## y ## _close((sph_haval_context*)cc, 0, 0, dst); \
} \
 \
void \
sph_haval ## xxx ## _ ## y ## addbits_and_close( \
	void *cc, unsigned ub, unsigned n, void *dst) \
{ \
	haval ## y ## _close((sph_haval_context*)cc, ub, n, dst); \
}

API(128, 3)
API(128, 4)
API(128, 5)
API(160, 3)
API(160, 4)
API(160, 5)
API(192, 3)
API(192, 4)
API(192, 5)
API(224, 3)
API(224, 4)
API(224, 5)
API(256, 3)
API(256, 4)
API(256, 5)

#define RVAL   do { \
		s0 = val[0]; \
		s1 = val[1]; \
		s2 = val[2]; \
		s3 = val[3]; \
		s4 = val[4]; \
		s5 = val[5]; \
		s6 = val[6]; \
		s7 = val[7]; \
	} while (0)

#define WVAL   do { \
		val[0] = s0; \
		val[1] = s1; \
		val[2] = s2; \
		val[3] = s3; \
		val[4] = s4; \
		val[5] = s5; \
		val[6] = s6; \
		val[7] = s7; \
	} while (0)

#define INMSG(i)   msg[i]

/* see sph_haval.h */
void
sph_haval_3_comp(const sph_u32 msg[32], sph_u32 val[8])
{
	DSTATE;

	RVAL;
	CORE3(INMSG);
	WVAL;
}

/* see sph_haval.h */
void
sph_haval_4_comp(const sph_u32 msg[32], sph_u32 val[8])
{
	DSTATE;

	RVAL;
	CORE4(INMSG);
	WVAL;
}

/* see sph_haval.h */
void
sph_haval_5_comp(const sph_u32 msg[32], sph_u32 val[8])
{
	DSTATE;

	RVAL;
	CORE5(INMSG);
	WVAL;
}
