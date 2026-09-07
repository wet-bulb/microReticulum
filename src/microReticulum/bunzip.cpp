// Capped bzip2 decompressor, decompress-only, single in-memory block.
//
// Public domain, after the design of Rob Landley's micro-bunzip. The inverse-
// BWT array is sized to the block's actual symbol count rather than the stream's
// declared maximum, and a block whose decompressed size would exceed the caller
// cap is rejected, so it runs where the reference decoder's fixed buffers would
// not fit. One stream, in memory, no files, no randomization (deprecated in
// bzip2 0.9.5, not emitted since).
#include "bunzip.h"
#include <string.h>
#include <stdlib.h>

namespace RNS {
#define BZ_GROUP_SIZE   50
#define BZ_MAX_GROUPS   6
#define BZ_MAX_SYMBOLS  258   /* 256 bytes - runs + RUNA/RUNB + EOB, bounded */
#define BZ_MAX_CODELEN  23
#define BZ_RUNA 0
#define BZ_RUNB 1

typedef struct {
	const uint8_t* in;
	size_t in_len;
	size_t in_pos;     /* byte position */
	uint32_t bitbuf;   /* MSB-first bit buffer */
	int bitcnt;        /* valid bits in bitbuf */
	int err;
} bitreader;

static uint32_t bits(bitreader* b, int n) {
	while (b->bitcnt < n) {
		if (b->in_pos >= b->in_len) { b->err = BUNZIP_EOF; return 0; }
		b->bitbuf = (b->bitbuf << 8) | b->in[b->in_pos++];
		b->bitcnt += 8;
	}
	b->bitcnt -= n;
	return (b->bitbuf >> b->bitcnt) & ((n == 32) ? 0xFFFFFFFFu : ((1u << n) - 1));
}

/* CRC32, bzip2 variant (MSB-first, init 0xffffffff, no final xism per byte). */
static uint32_t bz_crc_table[256];
static void bz_crc_init(void) {
	for (uint32_t i = 0; i < 256; ++i) {
		uint32_t c = i << 24;
		for (int k = 0; k < 8; ++k)
			c = (c & 0x80000000u) ? (c << 1) ^ 0x04c11db7u : (c << 1);
		bz_crc_table[i] = c;
	}
}
static inline uint32_t bz_crc_upd(uint32_t crc, uint8_t byte) {
	return (crc << 8) ^ bz_crc_table[((crc >> 24) ^ byte) & 0xff];
}

/* One Huffman group's canonical decode tables. */
typedef struct {
	int32_t limit[BZ_MAX_CODELEN + 2];
	int32_t base[BZ_MAX_CODELEN + 2];
	uint16_t perm[BZ_MAX_SYMBOLS];
	int minlen, maxlen;
} bz_group;

static void build_group(bz_group* g, const uint8_t* len, int symtot) {
	int minlen = 32, maxlen = 0;
	for (int s = 0; s < symtot; ++s) {
		if (len[s] > maxlen) maxlen = len[s];
		if (len[s] < minlen) minlen = len[s];
	}
	g->minlen = minlen; g->maxlen = maxlen;
	/* perm: symbols sorted by (length, symbol) */
	int pp = 0;
	for (int l = minlen; l <= maxlen; ++l)
		for (int s = 0; s < symtot; ++s)
			if (len[s] == l) g->perm[pp++] = (uint16_t)s;
	/* base / limit, the classic canonical-Huffman decode tables */
	int cnt[BZ_MAX_CODELEN + 2];
	for (int i = 0; i < BZ_MAX_CODELEN + 2; ++i) cnt[i] = 0;
	for (int s = 0; s < symtot; ++s) cnt[len[s] + 1]++;
	for (int i = 1; i < BZ_MAX_CODELEN + 2; ++i) cnt[i] += cnt[i - 1];
	for (int i = 0; i < BZ_MAX_CODELEN + 2; ++i) g->base[i] = cnt[i];
	int32_t vec = 0;
	for (int l = minlen; l <= maxlen; ++l) {
		vec += (g->base[l + 1] - g->base[l]);
		g->limit[l] = vec - 1;
		vec <<= 1;
	}
	for (int l = minlen + 1; l <= maxlen; ++l)
		g->base[l] = ((g->limit[l - 1] + 1) << 1) - g->base[l];
}

static int decode_sym(bitreader* b, const bz_group* g) {
	int l = g->minlen;
	int32_t v = (int32_t)bits(b, l);
	for (;;) {
		if (l > g->maxlen) { b->err = BUNZIP_DATA; return -1; }
		if (v <= g->limit[l]) break;
		v = (v << 1) | (int32_t)bits(b, 1);
		++l;
	}
	int idx = v - g->base[l];
	if (idx < 0 || idx >= BZ_MAX_SYMBOLS) { b->err = BUNZIP_DATA; return -1; }
	return g->perm[idx];
}

/*
 * Decompress `in`/`in_len` into `out` (capacity out_cap). tt is a caller-owned
 * scratch array of at least out_cap uint32_t. Returns decompressed length or a
 * negative BZ_ERR. Handles the multi-block case by concatenating blocks up to
 * the cap.
 */
int bunzip(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap,
           uint32_t* tt, size_t tt_cap) {
	static int crc_ready = 0;
	if (!crc_ready) { bz_crc_init(); crc_ready = 1; }

	bitreader b = { in, in_len, 0, 0, 0, 0 };

	if (bits(&b, 24) != 0x425A68u) return BUNZIP_MAGIC;   /* "BZh" */
	uint32_t level = bits(&b, 8);
	if (level < '1' || level > '9') return BUNZIP_MAGIC;

	size_t out_len = 0;

	for (;;) {
		uint32_t hi = bits(&b, 24), lo = bits(&b, 24);
		if (b.err) return b.err;
		if (hi == 0x177245u && lo == 0x385090u) break;       /* stream-end magic */
		if (hi != 0x314159u || lo != 0x265359u) return BUNZIP_HEADER; /* block magic */

		uint32_t block_crc = bits(&b, 32);
		if (bits(&b, 1)) return BUNZIP_UNSUP;                /* randomized */
		uint32_t orig_ptr = bits(&b, 24);

		/* Symbol map: which of 256 bytes are present. */
		uint16_t used16 = (uint16_t)bits(&b, 16);
		uint8_t sym_to_byte[256];
		int nInUse = 0;
		for (int i = 0; i < 16; ++i) {
			if (used16 & (0x8000 >> i)) {
				uint16_t bmap = (uint16_t)bits(&b, 16);
				for (int j = 0; j < 16; ++j)
					if (bmap & (0x8000 >> j)) sym_to_byte[nInUse++] = (uint8_t)(i * 16 + j);
			}
		}
		if (b.err) return b.err;
		if (nInUse == 0) return BUNZIP_DATA;
		int symTotal = nInUse + 2;   /* RUNA, RUNB, ..., EOB */

		int nGroups = (int)bits(&b, 3);
		int nSelectors = (int)bits(&b, 15);
		if (nGroups < 2 || nGroups > BZ_MAX_GROUPS || nSelectors < 1) return BUNZIP_DATA;

		/* Selectors: unary MTF values, then un-MTF. */
		uint8_t* selectors = (uint8_t*)malloc(nSelectors);
		if (!selectors) return BUNZIP_NOMEM;
		uint8_t gmtf[BZ_MAX_GROUPS];
		for (int i = 0; i < nGroups; ++i) gmtf[i] = (uint8_t)i;
		for (int i = 0; i < nSelectors; ++i) {
			int j = 0;
			while (bits(&b, 1)) { if (++j >= nGroups) { free(selectors); return BUNZIP_DATA; } }
			uint8_t v = gmtf[j];
			for (; j > 0; --j) gmtf[j] = gmtf[j - 1];
			gmtf[0] = v;
			selectors[i] = v;
		}
		if (b.err) { free(selectors); return b.err; }

		/* Huffman tables: delta-coded code lengths per group. */
		bz_group* groups = (bz_group*)malloc(sizeof(bz_group) * nGroups);
		if (!groups) { free(selectors); return BUNZIP_NOMEM; }
		for (int gi = 0; gi < nGroups; ++gi) {
			uint8_t len[BZ_MAX_SYMBOLS];
			int c = (int)bits(&b, 5);
			for (int s = 0; s < symTotal; ++s) {
				for (;;) {
					if (c < 1 || c > BZ_MAX_CODELEN) { free(selectors); free(groups); return BUNZIP_DATA; }
					if (!bits(&b, 1)) break;
					c += bits(&b, 1) ? -1 : 1;
				}
				len[s] = (uint8_t)c;
			}
			if (b.err) { free(selectors); free(groups); return b.err; }
			build_group(&groups[gi], len, symTotal);
		}

		/* Decode the MTF/RLE2 stream into the BWT byte array (tt low byte). */
		uint8_t mtf[256];
		for (int i = 0; i < nInUse; ++i) mtf[i] = sym_to_byte[i];
		int eob = symTotal - 1;
		size_t nblock = 0;
		int group_pos = 0, sel_idx = -1;
		const bz_group* g = NULL;
		int32_t run = 0, run_bit = 0;

		for (;;) {
			if (group_pos == 0) {
				if (++sel_idx >= nSelectors) { free(selectors); free(groups); return BUNZIP_DATA; }
				g = &groups[selectors[sel_idx]];
				group_pos = BZ_GROUP_SIZE;
			}
			--group_pos;
			int sym = decode_sym(&b, g);
			if (sym < 0) { free(selectors); free(groups); return BUNZIP_DATA; }

			if (sym == BZ_RUNA || sym == BZ_RUNB) {
				run += (sym == BZ_RUNA ? 1 : 2) << run_bit;
				++run_bit;
				continue;
			}
			/* flush a pending run of the front-of-MTF byte */
			if (run > 0) {
				uint8_t byte = mtf[0];
				if (nblock + (size_t)run > tt_cap) { free(selectors); free(groups); return BUNZIP_CAP; }
				for (int32_t r = 0; r < run; ++r) tt[nblock++] = byte;
				run = 0; run_bit = 0;
			}
			if (sym == eob) break;

			/* MTF decode: sym-1 is the index into the MTF list. */
			int idx = sym - 1;
			uint8_t byte = mtf[idx];
			memmove(&mtf[1], &mtf[0], idx);
			mtf[0] = byte;
			if (nblock >= tt_cap) { free(selectors); free(groups); return BUNZIP_CAP; }
			tt[nblock++] = byte;
		}
		free(selectors);
		free(groups);
		if (b.err) return b.err;
		if (orig_ptr >= nblock) return BUNZIP_DATA;

		/* Inverse BWT. Build cumulative counts, thread next-pointers into the
		 * high bits of tt, then walk from orig_ptr. */
		uint32_t cftab[257];
		for (int i = 0; i < 257; ++i) cftab[i] = 0;
		for (size_t i = 0; i < nblock; ++i) cftab[(tt[i] & 0xff) + 1]++;
		for (int i = 1; i < 257; ++i) cftab[i] += cftab[i - 1];
		for (size_t i = 0; i < nblock; ++i) {
			uint8_t ch = tt[i] & 0xff;
			tt[cftab[ch]] |= (uint32_t)(i << 8);
			cftab[ch]++;
		}

		/* Walk from orig_ptr, applying the inverse RLE1: a run of four equal
		 * bytes is followed by a count byte giving that many additional copies.
		 * The block CRC is over the decompressed (post-RLE1) bytes. */
		uint32_t tpos = tt[orig_ptr] >> 8;
		size_t bwt_left = nblock;
		uint32_t crc = 0xffffffffu;
		int run_len = 0;
		int run_byte = -1;
		while (bwt_left-- > 0) {
			uint8_t byte = tt[tpos] & 0xff;
			tpos = tt[tpos] >> 8;

			if (run_len == 4) {
				/* `byte` is the count of extra copies of run_byte, not data. */
				int extra = byte;
				if (out_len + (size_t)extra > out_cap) return BUNZIP_CAP;
				for (int r = 0; r < extra; ++r) {
					crc = bz_crc_upd(crc, (uint8_t)run_byte);
					out[out_len++] = (uint8_t)run_byte;
				}
				run_len = 0;
				run_byte = -1;
				continue;
			}

			if ((int)byte == run_byte) run_len++;
			else { run_len = 1; run_byte = byte; }

			if (out_len >= out_cap) return BUNZIP_CAP;
			crc = bz_crc_upd(crc, byte);
			out[out_len++] = byte;
		}
		crc ^= 0xffffffffu;
		if (crc != block_crc) return BUNZIP_CRC;
	}

	return (int)out_len;
}

}  // namespace RNS
