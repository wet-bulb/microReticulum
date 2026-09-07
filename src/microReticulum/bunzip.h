// Capped bzip2 decompressor, decompress-only. Public domain, after the design
// of Rob Landley's micro-bunzip. See bunzip.cpp for the full note.
//
// Resource responses are bz2-compressed by RNS (it emits BZh9). The reference
// libbzip2 sizes its inverse-BWT buffer to the stream's declared block size,
// up to 900 KB for BZh9, which does not fit on a small MCU. That size is the
// implementation's fixed allocation, not the algorithm's need: the array only
// has to hold the block's actual symbol count. This decoder sizes it to that
// and refuses a block whose decompressed size would exceed a caller cap, so a
// small resource decompresses in a few KB while a large one is rejected rather
// than allocated for.
#pragma once
#include <stdint.h>
#include <stddef.h>

namespace RNS {

// Largest resource this build will decompress. The inverse-BWT scratch is four
// bytes per decompressed byte, so a 24 KB cap costs ~96 KB of transient scratch.
// A host build with more RAM can raise it (e.g. -DRNS_BUNZIP_CAP=1048576).
#ifndef RNS_BUNZIP_CAP
#define RNS_BUNZIP_CAP 24576u
#endif

enum {
	BUNZIP_OK      = 0,
	BUNZIP_MAGIC   = -1,
	BUNZIP_HEADER  = -2,
	BUNZIP_DATA    = -3,
	BUNZIP_CAP     = -4,   // decompressed size would exceed the cap
	BUNZIP_EOF     = -5,
	BUNZIP_CRC     = -6,
	BUNZIP_NOMEM   = -7,
	BUNZIP_UNSUP   = -8,   // randomized block (never emitted since bzip2 0.9.5)
};

// Decompress `in`/`in_len` into `out` (capacity out_cap). `tt` is caller-owned
// scratch of at least out_cap uint32_t. Returns the decompressed length, or a
// negative BUNZIP_* error. No allocation of the large buffers happens inside.
int bunzip(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap,
           uint32_t* tt, size_t tt_cap);

}  // namespace RNS
