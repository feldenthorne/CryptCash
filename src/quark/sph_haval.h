/* $Id: sph_haval.h 218 2010-06-08 17:06:34Z tp $ */
/**
 * HAVAL interface.
 *
 * HAVAL is actually a family of 15 hash functions, depending on whether
 * the internal computation uses 3, 4 or 5 passes, and on the output
 * length, which is 128, 160, 192, 224 or 256 bits. This implementation
 * provides interface functions for all 15, which internally map to
 * three cores (depending on the number of passes). Note that output
 * lengths other than 256 bits are not obtained by a simple truncation
 * of a longer result; the requested length is encoded within the
 * padding data.
 *
 * HAVAL was published in: Yuliang Zheng, Josef Pieprzyk and Jennifer
 * Seberry: "HAVAL -- a one-way hashing algorithm with variable length
 * of output", Advances in Cryptology -- AUSCRYPT'92, Lecture Notes in
 * Computer Science, Vol.718, pp.83-104, Springer-Verlag, 1993.
 *
 * This paper, and a reference implementation, are available on the
 * Calyptix web site: http://labs.calyptix.com/haval.php
 *
 * The HAVAL reference paper is quite unclear on the data encoding
 * details, i.e. endianness (both byte order within a 32-bit word, and
 * word order within a message block). This implementation has been
 * made compatible with the reference implementation referenced above.
 *
 * @warning   A collision for HAVAL-128/3 (HAVAL with three passes and
 * 128-bit output) has been published; this function is thus considered
 * as cryptographically broken. The status for other variants is unclear;
 * use only with care.
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
 * @file     sph_haval.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_HAVAL_H__
#define SPH_HAVAL_H__

#ifdef __cplusplus
extern "C"{
#endif

#include <stddef.h>
#include <string.h>
#include "sph_types.h"

/**
 * Output size (in bits) for HAVAL-128/3.
 */
#define SPH_SIZE_haval128_3   128

/**
 * Output size (in bits) for HAVAL-128/4.
 */
#define SPH_SIZE_haval128_4   128

/**
 * Output size (in bits) for HAVAL-128/5.
 */
#define SPH_SIZE_haval128_5   128

/**
 * Output size (in bits) for HAVAL-160/3.
 */
#define SPH_SIZE_haval160_3   160

/**
 * Output size (in bits) for HAVAL-160/4.
 */
#define SPH_SIZE_haval160_4   160

/**
 * Output size (in bits) for HAVAL-160/5.
 */
#define SPH_SIZE_haval160_5   160

/**
 * Output size (in bits) for HAVAL-192/3.
 */
#define SPH_SIZE_haval192_3   192

/**
 * Output size (in bits) for HAVAL-192/4.
 */
#define SPH_SIZE_haval192_4   192

/**
 * Output size (in bits) for HAVAL-192/5.
 */
#define SPH_SIZE_haval192_5   192

/**
 * Output size (in bits) for HAVAL-224/3.
 */
#define SPH_SIZE_haval224_3   224

/**
 * Output size (in bits) for HAVAL-224/4.
 */
#define SPH_SIZE_haval224_4   224

/**
 * Output size (in bits) for HAVAL-224/5.
 */
#define SPH_SIZE_haval224_5   224

/**
 * Output size (in bits) for HAVAL-256/3.
 */
#define SPH_SIZE_haval256_3   256

/**
 * Output size (in bits) for HAVAL-256/4.
 */
#define SPH_SIZE_haval256_4   256

/**
 * Output size (in bits) for HAVAL-256/5.
 */
#define SPH_SIZE_haval256_5   256

/**
 * This structure is a context for HAVAL computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a HAVAL computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running HAVAL computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[128];    /* first field, for alignment */
	sph_u32 s0, s1, s2, s3, s4, s5, s6, s7;
	unsigned olen, passes;
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_haval_context;

/**
 * Type for a HAVAL-128/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval128_3_context;

/**
 * Type for a HAVAL-128/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval128_4_context;

/**
 * Type for a HAVAL-128/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval128_5_context;

/**
 * Type for a HAVAL-160/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval160_3_context;

/**
 * Type for a HAVAL-160/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval160_4_context;

/**
 * Type for a HAVAL-160/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval160_5_context;

/**
 * Type for a HAVAL-192/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval192_3_context;

/**
 * Type for a HAVAL-192/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval192_4_context;

/**
 * Type for a HAVAL-192/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval192_5_context;

/**
 * Type for a HAVAL-224/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval224_3_context;

/**
 * Type for a HAVAL-224/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval224_4_context;

/**
 * Type for a HAVAL-224/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval224_5_context;

/**
 * Type for a HAVAL-256/3 context (identical to the common context).
 */
typedef sph_haval_context sph_haval256_3_context;

/**
 * Type for a HAVAL-256/4 context (identical to the common context).
 */
typedef sph_haval_context sph_haval256_4_context;

/**
 * Type for a HAVAL-256/5 context (identical to the common context).
 */
typedef sph_haval_context sph_haval256_5_context;

/**
 * Initialize the context for HAVAL-128/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval128_3_context</code> structure)
 */
void sph_haval128_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-128/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-128/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval128_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-128/3 computation. The output buffer must be wide
 * enough to accomodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-128/3 context
 * @param dst   the output buffer
 */
void sph_haval128_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-128/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (16
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-128/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval128_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-128/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval128_4_context</code> structure)
 */
void sph_haval128_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-128/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-128/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval128_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-128/4 computation. The output buffer must be wide
 * enough to accomodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-128/4 context
 * @param dst   the output buffer
 */
void sph_haval128_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-128/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (16
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-128/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval128_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-128/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval128_5_context</code> structure)
 */
void sph_haval128_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-128/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-128/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval128_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-128/5 computation. The output buffer must be wide
 * enough to accomodate the result (16 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-128/5 context
 * @param dst   the output buffer
 */
void sph_haval128_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-128/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (16
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-128/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval128_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-160/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval160_3_context</code> structure)
 */
void sph_haval160_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-160/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-160/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval160_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-160/3 computation. The output buffer must be wide
 * enough to accomodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-160/3 context
 * @param dst   the output buffer
 */
void sph_haval160_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-160/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (20
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-160/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval160_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-160/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval160_4_context</code> structure)
 */
void sph_haval160_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-160/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-160/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval160_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-160/4 computation. The output buffer must be wide
 * enough to accomodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-160/4 context
 * @param dst   the output buffer
 */
void sph_haval160_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-160/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (20
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-160/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval160_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-160/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval160_5_context</code> structure)
 */
void sph_haval160_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-160/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-160/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval160_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-160/5 computation. The output buffer must be wide
 * enough to accomodate the result (20 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-160/5 context
 * @param dst   the output buffer
 */
void sph_haval160_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-160/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (20
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-160/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval160_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-192/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval192_3_context</code> structure)
 */
void sph_haval192_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-192/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-192/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval192_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-192/3 computation. The output buffer must be wide
 * enough to accomodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-192/3 context
 * @param dst   the output buffer
 */
void sph_haval192_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-192/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (24
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-192/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval192_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-192/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval192_4_context</code> structure)
 */
void sph_haval192_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-192/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-192/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval192_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-192/4 computation. The output buffer must be wide
 * enough to accomodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-192/4 context
 * @param dst   the output buffer
 */
void sph_haval192_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-192/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (24
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-192/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval192_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-192/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval192_5_context</code> structure)
 */
void sph_haval192_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-192/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-192/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval192_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-192/5 computation. The output buffer must be wide
 * enough to accomodate the result (24 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-192/5 context
 * @param dst   the output buffer
 */
void sph_haval192_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-192/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (24
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-192/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval192_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-224/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval224_3_context</code> structure)
 */
void sph_haval224_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-224/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-224/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval224_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-224/3 computation. The output buffer must be wide
 * enough to accomodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-224/3 context
 * @param dst   the output buffer
 */
void sph_haval224_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-224/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (28
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-224/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval224_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-224/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval224_4_context</code> structure)
 */
void sph_haval224_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-224/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-224/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval224_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-224/4 computation. The output buffer must be wide
 * enough to accomodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-224/4 context
 * @param dst   the output buffer
 */
void sph_haval224_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-224/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (28
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-224/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval224_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-224/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval224_5_context</code> structure)
 */
void sph_haval224_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-224/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-224/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval224_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-224/5 computation. The output buffer must be wide
 * enough to accomodate the result (28 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-224/5 context
 * @param dst   the output buffer
 */
void sph_haval224_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-224/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (28
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-224/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval224_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-256/3.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval256_3_context</code> structure)
 */
void sph_haval256_3_init(void *cc);

/**
 * Process some data bytes for HAVAL-256/3. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-256/3 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval256_3(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-256/3 computation. The output buffer must be wide
 * enough to accomodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-256/3 context
 * @param dst   the output buffer
 */
void sph_haval256_3_close(void *cc, void *dst);

/**
 * Close a HAVAL-256/3 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (32
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-256/3 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval256_3_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-256/4.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval256_4_context</code> structure)
 */
void sph_haval256_4_init(void *cc);

/**
 * Process some data bytes for HAVAL-256/4. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-256/4 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval256_4(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-256/4 computation. The output buffer must be wide
 * enough to accomodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-256/4 context
 * @param dst   the output buffer
 */
void sph_haval256_4_close(void *cc, void *dst);

/**
 * Close a HAVAL-256/4 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (32
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-256/4 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval256_4_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Initialize the context for HAVAL-256/5.
 *
 * @param cc   context to initialize (pointer to a
 *             <code>sph_haval256_5_context</code> structure)
 */
void sph_haval256_5_init(void *cc);

/**
 * Process some data bytes for HAVAL-256/5. If <code>len</code> is 0,
 * then this function does nothing.
 *
 * @param cc     the HAVAL-256/5 context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_haval256_5(void *cc, const void *data, size_t len);

/**
 * Close a HAVAL-256/5 computation. The output buffer must be wide
 * enough to accomodate the result (32 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the HAVAL-256/5 context
 * @param dst   the output buffer
 */
void sph_haval256_5_close(void *cc, void *dst);

/**
 * Close a HAVAL-256/5 computation. Up to 7 extra input bits may be added
 * to the input message; these are the <code>n</code> upper bits of
 * the <code>ub</code> byte (i.e. the first extra bit has value 128 in
 * <code>ub</code>, the second extra bit has value 64, and so on). Other
 * bits in <code>ub</code> are ignored.
 *
 * The output buffer must be wide enough to accomodate the result (32
 * bytes). The context is automatically reinitialized.
 *
 * @param cc    the HAVAL-256/5 context
 * @param ub    the extra bits
 * @param n     the number of extra bits (0 to 7)
 * @param dst   the output buffer
 */
void sph_haval256_5_addbits_and_close(void *cc,
	unsigned ub, unsigned n, void *dst);

/**
 * Apply the HAVAL compression function on the provided data. The
 * <code>msg</code> parameter contains the 32 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 8 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array. This function uses three internal passes.
 *
 * @param msg   the message block (32 values)
 * @param val   the function 256-bit input and output
 */
void sph_haval_3_comp(const sph_u32 msg[32], sph_u32 val[8]);

/**
 * Apply the HAVAL compression function on the provided data. The
 * <code>msg</code> parameter contains the 32 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 8 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array. This function uses four internal passes.
 *
 * @param msg   the message block (32 values)
 * @param val   the function 256-bit input and output
 */
void sph_haval_4_comp(const sph_u32 msg[32], sph_u32 val[8]);

/**
 * Apply the HAVAL compression function on the provided data. The
 * <code>msg</code> parameter contains the 32 32-bit input blocks,
 * as numerical values (hence after the little-endian decoding). The
 * <code>val</code> parameter contains the 8 32-bit input blocks for
 * the compression function; the output is written in place in this
 * array. This function uses five internal passes.
 *
 * @param msg   the message block (32 values)
 * @param val   the function 256-bit input and output
 */
void sph_haval_5_comp(const sph_u32 msg[32], sph_u32 val[8]);

/*
 * Basic definition from the reference paper.
 *
#define F1(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ ((x0) & (x1)) ^ (x0))
 *
 */

#define F1(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & ((x0) ^ (x4))) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ (x0))

/*
 * Basic definition from the reference paper.
 *
#define F2(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x2) & (x3)) ^ ((x2) & (x4) & (x5)) ^ ((x1) & (x2)) \
	^ ((x1) & (x4)) ^ ((x2) & (x6)) ^ ((x3) & (x5)) \
	^ ((x4) & (x5)) ^ ((x0) & (x2)) ^ (x0))
 *
 */

#define F2(x6, x5, x4, x3, x2, x1, x0) \
	(((x2) & (((x1) & ~(x3)) ^ ((x4) & (x5)) ^ (x6) ^ (x0))) \
	^ ((x4) & ((x1) ^ (x5))) ^ ((x3 & (x5)) ^ (x0)))

/*
 * Basic definition from the reference paper.
 *
#define F3(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x2) & (x3)) ^ ((x1) & (x4)) ^ ((x2) & (x5)) \
	^ ((x3) & (x6)) ^ ((x0) & (x3)) ^ (x0))
 *
 */

#define F3(x6, x5, x4, x3, x2, x1, x0) \
	(((x3) & (((x1) & (x2)) ^ (x6) ^ (x0))) \
	^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ (x0))

/*
 * Basic definition from the reference paper.
 *
#define F4(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x2) & (x3)) ^ ((x2) & (x4) & (x5)) ^ ((x3) & (x4) & (x6)) \
	^ ((x1) & (x4)) ^ ((x2) & (x6)) ^ ((x3) & (x4)) ^ ((x3) & (x5)) \
	^ ((x3) & (x6)) ^ ((x4) & (x5)) ^ ((x4) & (x6)) ^ ((x0) & (x4)) ^ (x0))
 *
 */

#define F4(x6, x5, x4, x3, x2, x1, x0) \
	(((x3) & (((x1) & (x2)) ^ ((x4) | (x6)) ^ (x5))) \
	^ ((x4) & ((~(x2) & (x5)) ^ (x1) ^ (x6) ^ (x0))) \
	^ ((x2) & (x6)) ^ (x0))

/*
 * Basic definition from the reference paper.
 *
#define F5(x6, x5, x4, x3, x2, x1, x0) \
	(((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)) \
	^ ((x0) & (x1) & (x2) & (x3)) ^ ((x0) & (x5)) ^ (x0))
 *
 */

#define F5(x6, x5, x4, x3, x2, x1, x0) \
	(((x0) & ~(((x1) & (x2) & (x3)) ^ (x5))) \
	^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)))

/*
 * The macros below integrate the phi() permutations, depending on the
 * pass and the total number of passes.
 */

#define FP3_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x1, x0, x3, x5, x6, x2, x4)
#define FP3_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x4, x2, x1, x0, x5, x3, x6)
#define FP3_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x6, x1, x2, x3, x4, x5, x0)

#define FP4_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x2, x6, x1, x4, x5, x3, x0)
#define FP4_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x3, x5, x2, x0, x1, x6, x4)
#define FP4_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x1, x4, x3, x6, x0, x2, x5)
#define FP4_4(x6, x5, x4, x3, x2, x1, x0) \
	F4(x6, x4, x0, x5, x2, x1, x3)

#define FP5_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x3, x4, x1, x0, x5, x2, x6)
#define FP5_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x6, x2, x1, x0, x3, x4, x5)
#define FP5_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x2, x6, x0, x4, x3, x1, x5)
#define FP5_4(x6, x5, x4, x3, x2, x1, x0) \
	F4(x1, x5, x3, x2, x0, x4, x6)
#define FP5_5(x6, x5, x4, x3, x2, x1, x0) \
	F5(x2, x5, x0, x6, x4, x3, x1)

/*
 * One step, for "n" passes, pass number "p" (1 <= p <= n), using
 * input word number "w" and step constant "c".
 */
#define STEP(n, p, x7, x6, x5, x4, x3, x2, x1, x0, w, c)  do { \
		sph_u32 t = FP ## n ## _ ## p(x6, x5, x4, x3, x2, x1, x0); \
		(x7) = SPH_T32(SPH_ROTR32(t, 7) + SPH_ROTR32((x7), 11) \
			+ (w) + (c)); \
	} while (0)

/*
 * PASSy(n, in) computes pass number "y", for a total of "n", using the
 * one-argument macro "in" to access input words. Current state is assumed
 * to be held in variables "s0" to "s7".
 */

#if SPH_SMALL_FOOTPRINT_HAVAL

#define PASS1(n, in)   do { \
		unsigned pass_count; \
		for (pass_count = 0; pass_count < 32; pass_count += 8) { \
			STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, \
				in(pass_count + 0), SPH_C32(0x00000000)); \
			STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, \
				in(pass_count + 1), SPH_C32(0x00000000)); \
			STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, \
				in(pass_count + 2), SPH_C32(0x00000000)); \
			STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, \
				in(pass_count + 3), SPH_C32(0x00000000)); \
			STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, \
				in(pass_count + 4), SPH_C32(0x00000000)); \
			STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, \
				in(pass_count + 5), SPH_C32(0x00000000)); \
			STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, \
				in(pass_count + 6), SPH_C32(0x00000000)); \
			STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, \
				in(pass_count + 7), SPH_C32(0x00000000)); \
   		} \
	} while (0)

#define PASSG(p, n, in)   do { \
		unsigned pass_count; \
		for (pass_count = 0; pass_count < 32; pass_count += 8) { \
			STEP(n, p, s7, s6, s5, s4, s3, s2, s1, s0, \
				in(MP ## p[pass_count + 0]), \
				RK ## p[pass_count + 0]); \
			STEP(n, p, s6, s5, s4, s3, s2, s1, s0, s7, \
				in(MP ## p[pass_count + 1]), \
				RK ## p[pass_count + 1]); \
			STEP(n, p, s5, s4, s3, s2, s1, s0, s7, s6, \
				in(MP ## p[pass_count + 2]), \
				RK ## p[pass_count + 2]); \
			STEP(n, p, s4, s3, s2, s1, s0, s7, s6, s5, \
				in(MP ## p[pass_count + 3]), \
				RK ## p[pass_count + 3]); \
			STEP(n, p, s3, s2, s1, s0, s7, s6, s5, s4, \
				in(MP ## p[pass_count + 4]), \
				RK ## p[pass_count + 4]); \
			STEP(n, p, s2, s1, s0, s7, s6, s5, s4, s3, \
				in(MP ## p[pass_count + 5]), \
				RK ## p[pass_count + 5]); \
			STEP(n, p, s1, s0, s7, s6, s5, s4, s3, s2, \
				in(MP ## p[pass_count + 6]), \
				RK ## p[pass_count + 6]); \
			STEP(n, p, s0, s7, s6, s5, s4, s3, s2, s1, \
				in(MP ## p[pass_count + 7]), \
				RK ## p[pass_count + 7]); \
   		} \
	} while (0)

#define PASS2(n, in)    PASSG(2, n, in)
#define PASS3(n, in)    PASSG(3, n, in)
#define PASS4(n, in)    PASSG(4, n, in)
#define PASS5(n, in)    PASSG(5, n, in)

static const unsigned MP2[32] = {
	 5, 14, 26, 18, 11, 28,  7, 16,
	 0, 23, 20, 22,  1, 10,  4,  8,
	30,  3, 21,  9, 17, 24, 29,  6,
	19, 12, 15, 13,  2, 25, 31, 27
};

static const unsigned MP3[32] = {
	19,  9,  4, 20, 28, 17,  8, 22,
	29, 14, 25, 12, 24, 30, 16, 26,
	31, 15,  7,  3,  1,  0, 18, 27,
	13,  6, 21, 10, 23, 11,  5,  2
};

static const unsigned MP4[32] = {
	24,  4,  0, 14,  2,  7, 28, 23,
	26,  6, 30, 20, 18, 25, 19,  3,
	22, 11, 31, 21,  8, 27, 12,  9,
	 1, 29,  5, 15, 17, 10, 16, 13
};

static const unsigned MP5[32] = {
	27,  3, 21, 26, 17, 11, 20, 29,
	19,  0, 12,  7, 13,  8, 31, 10,
	 5,  9, 14, 30, 18,  6, 28, 24,
	 2, 23, 16, 22,  4,  1, 25, 15
};

static const sph_u32 RK2[32] = {
	SPH_C32(0x452821E6), SPH_C32(0x38D01377),
	SPH_C32(0xBE5466CF), SPH_C32(0x34E90C6C),
	SPH_C32(0xC0AC29B7), SPH_C32(0xC97C50DD),
	SPH_C32(0x3F84D5B5), SPH_C32(0xB5470917),
	SPH_C32(0x9216D5D9), SPH_C32(0x8979FB1B),
	SPH_C32(0xD1310BA6), SPH_C32(0x98DFB5AC),
	SPH_C32(0x2FFD72DB), SPH_C32(0xD01ADFB7),
	SPH_C32(0xB8E1AFED), SPH_C32(0x6A267E96),
	SPH_C32(0xBA7C9045), SPH_C32(0xF12C7F99),
	SPH_C32(0x24A19947), SPH_C32(0xB3916CF7),
	SPH_C32(0x0801F2E2), SPH_C32(0x858EFC16),
	SPH_C32(0x636920D8), SPH_C32(0x71574E69),
	SPH_C32(0xA458FEA3), SPH_C32(0xF4933D7E),
	SPH_C32(0x0D95748F), SPH_C32(0x728EB658),
	SPH_C32(0x718BCD58), SPH_C32(0x82154AEE),
	SPH_C32(0x7B54A41D), SPH_C32(0xC25A59B5)
};

static const sph_u32 RK3[32] = {
	SPH_C32(0x9C30D539), SPH_C32(0x2AF26013),
	SPH_C32(0xC5D1B023), SPH_C32(0x286085F0),
	SPH_C32(0xCA417918), SPH_C32(0xB8DB38EF),
	SPH_C32(0x8E79DCB0), SPH_C32(0x603A180E),
	SPH_C32(0x6C9E0E8B), SPH_C32(0xB01E8A3E),
	SPH_C32(0xD71577C1), SPH_C32(0xBD314B27),
	SPH_C32(0x78AF2FDA), SPH_C32(0x55605C60),
	SPH_C32(0xE65525F3), SPH_C32(0xAA55AB94),
	SPH_C32(0x57489862), SPH_C32(0x63E81440),
	SPH_C32(0x55CA396A), SPH_C32(0x2AAB10B6),
	SPH_C32(0xB4CC5C34), SPH_C32(0x1141E8CE),
	SPH_C32(0xA15486AF), SPH_C32(0x7C72E993),
	SPH_C32(0xB3EE1411), SPH_C32(0x636FBC2A),
	SPH_C32(0x2BA9C55D), SPH_C32(0x741831F6),
	SPH_C32(0xCE5C3E16), SPH_C32(0x9B87931E),
	SPH_C32(0xAFD6BA33), SPH_C32(0x6C24CF5C)
};

static const sph_u32 RK4[32] = {
	SPH_C32(0x7A325381), SPH_C32(0x28958677),
	SPH_C32(0x3B8F4898), SPH_C32(0x6B4BB9AF),
	SPH_C32(0xC4BFE81B), SPH_C32(0x66282193),
	SPH_C32(0x61D809CC), SPH_C32(0xFB21A991),
	SPH_C32(0x487CAC60), SPH_C32(0x5DEC8032),
	SPH_C32(0xEF845D5D), SPH_C32(0xE98575B1),
	SPH_C32(0xDC262302), SPH_C32(0xEB651B88),
	SPH_C32(0x23893E81), SPH_C32(0xD396ACC5),
	SPH_C32(0x0F6D6FF3), SPH_C32(0x83F44239),
	SPH_C32(0x2E0B4482), SPH_C32(0xA4842004),
	SPH_C32(0x69C8F04A), SPH_C32(0x9E1F9B5E),
	SPH_C32(0x21C66842), SPH_C32(0xF6E96C9A),
	SPH_C32(0x670C9C61), SPH_C32(0xABD388F0),
	SPH_C32(0x6A51A0D2), SPH_C32(0xD8542F68),
	SPH_C32(0x960FA728), SPH_C32(0xAB5133A3),
	SPH_C32(0x6EEF0B6C), SPH_C32(0x137A3BE4)
};

static const sph_u32 RK5[32] = {
	SPH_C32(0xBA3BF050), SPH_C32(0x7EFB2A98),
	SPH_C32(0xA1F1651D), SPH_C32(0x39AF0176),
	SPH_C32(0x66CA593E), SPH_C32(0x82430E88),
	SPH_C32(0x8CEE8619), SPH_C32(0x456F9FB4),
	SPH_C32(0x7D84A5C3), SPH_C32(0x3B8B5EBE),
	SPH_C32(0xE06F75D8), SPH_C32(0x85C12073),
	SPH_C32(0x401A449F), SPH_C32(0x56C16AA6),
	SPH_C32(0x4ED3AA62), SPH_C32(0x363F7706),
	SPH_C32(0x1BFEDF72), SPH_C32(0x429B023D),
	SPH_C32(0x37D0D724), SPH_C32(0xD00A1248),
	SPH_C32(0xDB0FEAD3), SPH_C32(0x49F1C09B),
	SPH_C32(0x075372C9), SPH_C32(0x80991B7B),
	SPH_C32(0x25D479D8), SPH_C32(0xF6E8DEF7),
	SPH_C32(0xE3FE501A), SPH_C32(0xB6794C3B),
	SPH_C32(0x976CE0BD), SPH_C32(0x04C006BA),
	SPH_C32(0xC1A94FB6), SPH_C32(0x409F60C4)
};

#else

#define PASS1(n, in)   do { \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in( 0), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in( 1), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in( 2), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in( 3), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in( 4), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in( 5), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in( 6), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in( 7), SPH_C32(0x00000000)); \
 \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in( 8), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in( 9), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in(10), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in(11), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in(12), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in(13), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in(14), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in(15), SPH_C32(0x00000000)); \
 \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in(16), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in(17), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in(18), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in(19), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in(20), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in(21), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in(22), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in(23), SPH_C32(0x00000000)); \
 \
   STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, in(24), SPH_C32(0x00000000)); \
   STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, in(25), SPH_C32(0x00000000)); \
   STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, in(26), SPH_C32(0x00000000)); \
   STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, in(27), SPH_C32(0x00000000)); \
   STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, in(28), SPH_C32(0x00000000)); \
   STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, in(29), SPH_C32(0x00000000)); \
   STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, in(30), SPH_C32(0x00000000)); \
   STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, in(31), SPH_C32(0x00000000)); \
	} while (0)

#define PASS2(n, in)   do { \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in( 5), SPH_C32(0x452821E6)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in(14), SPH_C32(0x38D01377)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(26), SPH_C32(0xBE5466CF)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in(18), SPH_C32(0x34E90C6C)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in(11), SPH_C32(0xC0AC29B7)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(28), SPH_C32(0xC97C50DD)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in( 7), SPH_C32(0x3F84D5B5)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in(16), SPH_C32(0xB5470917)); \
 \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in( 0), SPH_C32(0x9216D5D9)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in(23), SPH_C32(0x8979FB1B)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(20), SPH_C32(0xD1310BA6)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in(22), SPH_C32(0x98DFB5AC)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in( 1), SPH_C32(0x2FFD72DB)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(10), SPH_C32(0xD01ADFB7)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in( 4), SPH_C32(0xB8E1AFED)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in( 8), SPH_C32(0x6A267E96)); \
 \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in(30), SPH_C32(0xBA7C9045)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in( 3), SPH_C32(0xF12C7F99)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(21), SPH_C32(0x24A19947)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in( 9), SPH_C32(0xB3916CF7)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in(17), SPH_C32(0x0801F2E2)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(24), SPH_C32(0x858EFC16)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in(29), SPH_C32(0x636920D8)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in( 6), SPH_C32(0x71574E69)); \
 \
   STEP(n, 2, s7, s6, s5, s4, s3, s2, s1, s0, in(19), SPH_C32(0xA458FEA3)); \
   STEP(n, 2, s6, s5, s4, s3, s2, s1, s0, s7, in(12), SPH_C32(0xF4933D7E)); \
   STEP(n, 2, s5, s4, s3, s2, s1, s0, s7, s6, in(15), SPH_C32(0x0D95748F)); \
   STEP(n, 2, s4, s3, s2, s1, s0, s7, s6, s5, in(13), SPH_C32(0x728EB658)); \
   STEP(n, 2, s3, s2, s1, s0, s7, s6, s5, s4, in( 2), SPH_C32(0x718BCD58)); \
   STEP(n, 2, s2, s1, s0, s7, s6, s5, s4, s3, in(25), SPH_C32(0x82154AEE)); \
   STEP(n, 2, s1, s0, s7, s6, s5, s4, s3, s2, in(31), SPH_C32(0x7B54A41D)); \
   STEP(n, 2, s0, s7, s6, s5, s4, s3, s2, s1, in(27), SPH_C32(0xC25A59B5)); \
	} while (0)

#define PASS3(n, in)   do { \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(19), SPH_C32(0x9C30D539)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in( 9), SPH_C32(0x2AF26013)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in( 4), SPH_C32(0xC5D1B023)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in(20), SPH_C32(0x286085F0)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in(28), SPH_C32(0xCA417918)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in(17), SPH_C32(0xB8DB38EF)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in( 8), SPH_C32(0x8E79DCB0)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in(22), SPH_C32(0x603A180E)); \
 \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(29), SPH_C32(0x6C9E0E8B)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in(14), SPH_C32(0xB01E8A3E)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in(25), SPH_C32(0xD71577C1)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in(12), SPH_C32(0xBD314B27)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in(24), SPH_C32(0x78AF2FDA)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in(30), SPH_C32(0x55605C60)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in(16), SPH_C32(0xE65525F3)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in(26), SPH_C32(0xAA55AB94)); \
 \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(31), SPH_C32(0x57489862)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in(15), SPH_C32(0x63E81440)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in( 7), SPH_C32(0x55CA396A)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in( 3), SPH_C32(0x2AAB10B6)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in( 1), SPH_C32(0xB4CC5C34)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in( 0), SPH_C32(0x1141E8CE)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in(18), SPH_C32(0xA15486AF)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in(27), SPH_C32(0x7C72E993)); \
 \
   STEP(n, 3, s7, s6, s5, s4, s3, s2, s1, s0, in(13), SPH_C32(0xB3EE1411)); \
   STEP(n, 3, s6, s5, s4, s3, s2, s1, s0, s7, in( 6), SPH_C32(0x636FBC2A)); \
   STEP(n, 3, s5, s4, s3, s2, s1, s0, s7, s6, in(21), SPH_C32(0x2BA9C55D)); \
   STEP(n, 3, s4, s3, s2, s1, s0, s7, s6, s5, in(10), SPH_C32(0x741831F6)); \
   STEP(n, 3, s3, s2, s1, s0, s7, s6, s5, s4, in(23), SPH_C32(0xCE5C3E16)); \
   STEP(n, 3, s2, s1, s0, s7, s6, s5, s4, s3, in(11), SPH_C32(0x9B87931E)); \
   STEP(n, 3, s1, s0, s7, s6, s5, s4, s3, s2, in( 5), SPH_C32(0xAFD6BA33)); \
   STEP(n, 3, s0, s7, s6, s5, s4, s3, s2, s1, in( 2), SPH_C32(0x6C24CF5C)); \
	} while (0)

#define PASS4(n, in)   do { \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in(24), SPH_C32(0x7A325381)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in( 4), SPH_C32(0x28958677)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in( 0), SPH_C32(0x3B8F4898)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(14), SPH_C32(0x6B4BB9AF)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in( 2), SPH_C32(0xC4BFE81B)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in( 7), SPH_C32(0x66282193)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(28), SPH_C32(0x61D809CC)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in(23), SPH_C32(0xFB21A991)); \
 \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in(26), SPH_C32(0x487CAC60)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in( 6), SPH_C32(0x5DEC8032)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in(30), SPH_C32(0xEF845D5D)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(20), SPH_C32(0xE98575B1)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in(18), SPH_C32(0xDC262302)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in(25), SPH_C32(0xEB651B88)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(19), SPH_C32(0x23893E81)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in( 3), SPH_C32(0xD396ACC5)); \
 \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in(22), SPH_C32(0x0F6D6FF3)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in(11), SPH_C32(0x83F44239)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in(31), SPH_C32(0x2E0B4482)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(21), SPH_C32(0xA4842004)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in( 8), SPH_C32(0x69C8F04A)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in(27), SPH_C32(0x9E1F9B5E)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(12), SPH_C32(0x21C66842)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in( 9), SPH_C32(0xF6E96C9A)); \
 \
   STEP(n, 4, s7, s6, s5, s4, s3, s2, s1, s0, in( 1), SPH_C32(0x670C9C61)); \
   STEP(n, 4, s6, s5, s4, s3, s2, s1, s0, s7, in(29), SPH_C32(0xABD388F0)); \
   STEP(n, 4, s5, s4, s3, s2, s1, s0, s7, s6, in( 5), SPH_C32(0x6A51A0D2)); \
   STEP(n, 4, s4, s3, s2, s1, s0, s7, s6, s5, in(15), SPH_C32(0xD8542F68)); \
   STEP(n, 4, s3, s2, s1, s0, s7, s6, s5, s4, in(17), SPH_C32(0x960FA728)); \
   STEP(n, 4, s2, s1, s0, s7, s6, s5, s4, s3, in(10), SPH_C32(0xAB5133A3)); \
   STEP(n, 4, s1, s0, s7, s6, s5, s4, s3, s2, in(16), SPH_C32(0x6EEF0B6C)); \
   STEP(n, 4, s0, s7, s6, s5, s4, s3, s2, s1, in(13), SPH_C32(0x137A3BE4)); \
	} while (0)

#define PASS5(n, in)   do { \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in(27), SPH_C32(0xBA3BF050)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in( 3), SPH_C32(0x7EFB2A98)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(21), SPH_C32(0xA1F1651D)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in(26), SPH_C32(0x39AF0176)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in(17), SPH_C32(0x66CA593E)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in(11), SPH_C32(0x82430E88)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(20), SPH_C32(0x8CEE8619)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(29), SPH_C32(0x456F9FB4)); \
 \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in(19), SPH_C32(0x7D84A5C3)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in( 0), SPH_C32(0x3B8B5EBE)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(12), SPH_C32(0xE06F75D8)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in( 7), SPH_C32(0x85C12073)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in(13), SPH_C32(0x401A449F)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in( 8), SPH_C32(0x56C16AA6)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(31), SPH_C32(0x4ED3AA62)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(10), SPH_C32(0x363F7706)); \
 \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in( 5), SPH_C32(0x1BFEDF72)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in( 9), SPH_C32(0x429B023D)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(14), SPH_C32(0x37D0D724)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in(30), SPH_C32(0xD00A1248)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in(18), SPH_C32(0xDB0FEAD3)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in( 6), SPH_C32(0x49F1C09B)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(28), SPH_C32(0x075372C9)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(24), SPH_C32(0x80991B7B)); \
 \
   STEP(n, 5, s7, s6, s5, s4, s3, s2, s1, s0, in( 2), SPH_C32(0x25D479D8)); \
   STEP(n, 5, s6, s5, s4, s3, s2, s1, s0, s7, in(23), SPH_C32(0xF6E8DEF7)); \
   STEP(n, 5, s5, s4, s3, s2, s1, s0, s7, s6, in(16), SPH_C32(0xE3FE501A)); \
   STEP(n, 5, s4, s3, s2, s1, s0, s7, s6, s5, in(22), SPH_C32(0xB6794C3B)); \
   STEP(n, 5, s3, s2, s1, s0, s7, s6, s5, s4, in( 4), SPH_C32(0x976CE0BD)); \
   STEP(n, 5, s2, s1, s0, s7, s6, s5, s4, s3, in( 1), SPH_C32(0x04C006BA)); \
   STEP(n, 5, s1, s0, s7, s6, s5, s4, s3, s2, in(25), SPH_C32(0xC1A94FB6)); \
   STEP(n, 5, s0, s7, s6, s5, s4, s3, s2, s1, in(15), SPH_C32(0x409F60C4)); \
	} while (0)

#endif

#define SAVE_STATE \
	sph_u32 u0, u1, u2, u3, u4, u5, u6, u7; \
	do { \
		u0 = s0; \
		u1 = s1; \
		u2 = s2; \
		u3 = s3; \
		u4 = s4; \
		u5 = s5; \
		u6 = s6; \
		u7 = s7; \
	} while (0)

#define UPDATE_STATE   do { \
		s0 = SPH_T32(s0 + u0); \
		s1 = SPH_T32(s1 + u1); \
		s2 = SPH_T32(s2 + u2); \
		s3 = SPH_T32(s3 + u3); \
		s4 = SPH_T32(s4 + u4); \
		s5 = SPH_T32(s5 + u5); \
		s6 = SPH_T32(s6 + u6); \
		s7 = SPH_T32(s7 + u7); \
	} while (0)

/*
 * COREn(in) performs the core HAVAL computation for "n" passes, using
 * the one-argument macro "in" to access the input words. Running state
 * is held in variable "s0" to "s7".
 */

#define CORE3(in)  do { \
		SAVE_STATE; \
		PASS1(3, in); \
		PASS2(3, in); \
		PASS3(3, in); \
		UPDATE_STATE; \
	} while (0)

#define CORE4(in)  do { \
		SAVE_STATE; \
		PASS1(4, in); \
		PASS2(4, in); \
		PASS3(4, in); \
		PASS4(4, in); \
		UPDATE_STATE; \
	} while (0)

#define CORE5(in)  do { \
		SAVE_STATE; \
		PASS1(5, in); \
		PASS2(5, in); \
		PASS3(5, in); \
		PASS4(5, in); \
		PASS5(5, in); \
		UPDATE_STATE; \
	} while (0)

/*
 * DSTATE declares the state variables "s0" to "s7".
 */
#define DSTATE   sph_u32 s0, s1, s2, s3, s4, s5, s6, s7

/*
 * RSTATE fills the state variables from the context "sc".
 */
#define RSTATE   do { \
		s0 = sc->s0; \
		s1 = sc->s1; \
		s2 = sc->s2; \
		s3 = sc->s3; \
		s4 = sc->s4; \
		s5 = sc->s5; \
		s6 = sc->s6; \
		s7 = sc->s7; \
	} while (0)

/*
 * WSTATE updates the context "sc" from the state variables.
 */
#define WSTATE   do { \
		sc->s0 = s0; \
		sc->s1 = s1; \
		sc->s2 = s2; \
		sc->s3 = s3; \
		sc->s4 = s4; \
		sc->s5 = s5; \
		sc->s6 = s6; \
		sc->s7 = s7; \
	} while (0)

/*
 * IN_PREPARE(data) contains declarations and code to prepare for
 * reading input words pointed to by "data".
 * INW(i) reads the word number "i" (from 0 to 31).
 */
#define IN_PREPARE(indata) \
	sph_u32 X_var[32]; \
	int load_index; \
 \
	for (load_index = 0; load_index < 32; load_index ++) \
		X_var[load_index] = sph_dec32le_aligned( \
			(const unsigned char *)(indata) + 4 * load_index)
#define INW(i)   X_var[i]

#ifdef __cplusplus
}
#endif

#endif
