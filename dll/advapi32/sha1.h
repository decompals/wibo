/*
SHA-1 hashing. Choice of public domain or MIT-0. See license statements at the end of this file.

David Reid - mackron@gmail.com
*/

/*
A simple SHA-1 hashing implementation. Usage:

    unsigned char digest[SHA1_SIZE];
    sha1_context ctx;
    sha1_init(&ctx);
    {
        sha1_update(&ctx, src, sz);
    }
    sha1_finalize(&ctx, digest);

The above code is the literal implementation of `sha1()` which is a high level helper for hashing
data of a known size:

    unsigned char hash[SHA1_SIZE];
    sha1(hash, data, dataSize);

Use `sha1_format()` to format the digest as a hex string. The capacity of the output buffer needs to
be at least `SHA1_SIZE_FORMATTED` bytes.

This library does not perform any memory allocations and does not use anything from the standard
library except for `size_t` and `NULL`, both of which are drawn in from stddef.h. No other standard
headers are included.

There is no need to link to anything with this library. You can use SHA1_IMPLEMENTATION to define
the implementation section, or you can use sha1.c if you prefer a traditional header/source pair.

This implements both methods defined in RFC 3174. Method 1 will be used by default. If you want to
use Method 2, define `SHA1_USE_RFC_METHOD_2` at compile time.

    #define SHA1_USE_RFC_METHOD_2
    #define SHA1_IMPLEMENTATION
    #include "sha1.h"

No effort has been made to optimize this beyond the algorithms described in RGC 3174. If you're
looking for the fastest SHA-1 implementation you'll need to look elsewhere. An optimized
implementation may come later.
*/
#ifndef sha1_h
#define sha1_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h> /* For size_t and NULL. */

#if defined(_MSC_VER)
    typedef unsigned __int64   sha1_uint64;
#else
    typedef unsigned long long sha1_uint64;
#endif

#if !defined(SHA1_API)
    #define SHA1_API
#endif

#define SHA1_SIZE            20
#define SHA1_SIZE_FORMATTED  41

typedef struct
{
    unsigned int h[5];
    sha1_uint64 sz;
    unsigned char cache[64];
    unsigned int cacheLen;
} sha1_context;

SHA1_API void sha1_init(sha1_context* ctx);
SHA1_API void sha1_update(sha1_context* ctx, const void* src, size_t sz);
SHA1_API void sha1_finalize(sha1_context* ctx, unsigned char* digest);
SHA1_API void sha1(unsigned char* digest, const void* src, size_t sz);
SHA1_API void sha1_format(char* dst, size_t dstCap, const unsigned char* hash);

#ifdef __cplusplus
}
#endif
#endif  /* sha1_h */

#if defined(SHA1_IMPLEMENTATION)
#ifndef sha1_c
#define sha1_c

#define SHA1_ALGORITHM_RFC_METHOD_1 1
#define SHA1_ALGORITHM_RFC_METHOD_2 2
#define SHA1_ALGORITHM_DEFAULT      SHA1_ALGORITHM_RFC_METHOD_1

#  if defined(SHA1_USE_RFC_METHOD_1)
    #define SHA1_ALGORITHM SHA1_ALGORITHM_RFC_METHOD_1
#elif defined(SHA1_USE_RFC_METHOD_2)
    #define SHA1_ALGORITHM SHA1_ALGORITHM_RFC_METHOD_2
#else
    #define SHA1_ALGORITHM SHA1_ALGORITHM_DEFAULT
#endif


static void sha1_zero_memory(void* p, size_t sz)
{
    size_t i;
    for (i = 0; i < sz; i += 1) {
        ((unsigned char*)p)[i] = 0;
    }
}

static void sha1_copy_memory(void* dst, const void* src, size_t sz)
{
    size_t i;
    for (i = 0; i < sz; i += 1) {
        ((unsigned char*)dst)[i] = ((unsigned char*)src)[i];
    }
}


#define SHA1_ROTATE_LEFT(x, n)  (((x) << (n)) | ((x) >> (32 - (n))))

#define SHA1_F00(b, c, d)       (((b) & (c)) | ((~(b)) & (d)))              /* (B AND C) OR ((NOT B) AND D) */
#define SHA1_F20(b, c, d)       ((b) ^ (c) ^ (d))                           /* B XOR C XOR D */
#define SHA1_F40(b, c, d)       (((b) & (c)) | ((b) & (d)) | ((c) & (d)))   /* (B AND C) OR (B AND D) OR (C AND D) */
#define SHA1_F60(b, c, d)       ((b) ^ (c) ^ (d))                           /* B XOR C XOR D */

/*
This is the main SHA-1 function. Everything is processed in blocks of 64 bytes.
*/
static void sha1_update_block(sha1_context* ctx, const unsigned char* src)
{
    size_t i;
    unsigned int w[80];
    unsigned int a, b, c, d, e;
    unsigned int temp;

    /* assert(ctx != NULL); */
    /* assert(src != NULL); */
    
    for (i = 0; i < 16; i += 1) {
        w[i]  = (src[i*4 + 0] << 24);
        w[i] |= (src[i*4 + 1] << 16);
        w[i] |= (src[i*4 + 2] <<  8);
        w[i] |= (src[i*4 + 3] <<  0);
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];

#if SHA1_ALGORITHM == SHA1_ALGORITHM_RFC_METHOD_1
    {
        for (i = 16; i < 80; i += 1) {
            w[i] = SHA1_ROTATE_LEFT((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
        }

        for (i = 0; i < 20; i += 1) {
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F00(b, c, d) + e + w[i] + 0x5A827999;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 20; i < 40; i += 1) {
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F20(b, c, d) + e + w[i] + 0x6ED9EBA1;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 40; i < 60; i += 1) {
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F40(b, c, d) + e + w[i] + 0x8F1BBCDC;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 60; i < 80; i += 1) {
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F60(b, c, d) + e + w[i] + 0xCA62C1D6;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }
    }
#endif

#if SHA1_ALGORITHM == SHA1_ALGORITHM_RFC_METHOD_2
    {
        unsigned int mask = 0x0000000F;
        unsigned int s;

        for (i = 0; i < 16; i += 1) {
            s = i & mask;
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F00(b, c, d) + e + w[s] + 0x5A827999;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 16; i < 20; i += 1) {
            s = i & mask;
            w[s] = SHA1_ROTATE_LEFT(w[(s + 13) & mask] ^ w[(s + 8) & mask] ^ w[(s + 2) & mask] ^ w[s], 1);
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F00(b, c, d) + e + w[s] + 0x5A827999;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 20; i < 40; i += 1) {
            s = i & mask;
            w[s] = SHA1_ROTATE_LEFT(w[(s + 13) & mask] ^ w[(s + 8) & mask] ^ w[(s + 2) & mask] ^ w[s], 1);
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F20(b, c, d) + e + w[s] + 0x6ED9EBA1;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 40; i < 60; i += 1) {
            s = i & mask;
            w[s] = SHA1_ROTATE_LEFT(w[(s + 13) & mask] ^ w[(s + 8) & mask] ^ w[(s + 2) & mask] ^ w[s], 1);
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F40(b, c, d) + e + w[s] + 0x8F1BBCDC;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }

        for (i = 60; i < 80; i += 1) {
            s = i & mask;
            w[s] = SHA1_ROTATE_LEFT(w[(s + 13) & mask] ^ w[(s + 8) & mask] ^ w[(s + 2) & mask] ^ w[s], 1);
            temp = SHA1_ROTATE_LEFT(a, 5) + SHA1_F60(b, c, d) + e + w[s] + 0xCA62C1D6;
            e = d;
            d = c;
            c = SHA1_ROTATE_LEFT(b, 30);
            b = a;
            a = temp;
        }
    }
#endif
    
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    
    /* We'll only ever be calling this if the context's cache is full. At this point the cache will also be empty. */
    ctx->cacheLen = 0;
}

SHA1_API void sha1_init(sha1_context* ctx)
{
    if (ctx == NULL) {
        return;
    }

    sha1_zero_memory(ctx, sizeof(*ctx));

    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
}

SHA1_API void sha1_update(sha1_context* ctx, const void* src, size_t sz)
{
    const unsigned char* bytes = (const unsigned char*)src;
    size_t totalBytesProcessed = 0;

    if (ctx == NULL || (src == NULL && sz > 0)) {
        return;
    }

    /* Keep processing until all data has been exhausted. */
    while (totalBytesProcessed < sz) {
        /* Optimization. Bypass the cache if there's nothing in it and the number of bytes remaining to process is larger than 64. */
        size_t bytesRemainingToProcess = sz - totalBytesProcessed;
        if (ctx->cacheLen == 0 && bytesRemainingToProcess > sizeof(ctx->cache)) {
            /* Fast path. Bypass the cache and just process directly. */
            sha1_update_block(ctx, bytes + totalBytesProcessed);
            totalBytesProcessed += sizeof(ctx->cache);
        } else {
            /* Slow path. Need to store in the cache. */
            size_t cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
            if (cacheRemaining > 0) {
                /* There's still some room left in the cache. Write as much data to it as we can. */
                size_t bytesToProcess = bytesRemainingToProcess;
                if (bytesToProcess > cacheRemaining) {
                    bytesToProcess = cacheRemaining;
                }

                sha1_copy_memory(ctx->cache + ctx->cacheLen, bytes + totalBytesProcessed, bytesToProcess);
                ctx->cacheLen       += (unsigned int)bytesToProcess;    /* Safe cast. bytesToProcess will always be <= sizeof(ctx->cache) which is 64. */
                totalBytesProcessed +=               bytesToProcess;

                /* Update the number of bytes remaining in the cache so we can use it later. */
                cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
            }

            /* If the cache is full, get it processed. */
            if (cacheRemaining == 0) {
                sha1_update_block(ctx, ctx->cache);
            }
        }
    }

    ctx->sz += sz;
}

SHA1_API void sha1_finalize(sha1_context* ctx, unsigned char* digest)
{
    size_t cacheRemaining;
    unsigned int szLo;
    unsigned int szHi;

    if (digest == NULL) {
        return;
    }

    if (ctx == NULL) {
        sha1_zero_memory(digest, SHA1_SIZE);
        return;
    }

    /*
    Padding must be applied. First thing to do is clear the cache if there's no room for at least
    one byte. This should never happen, but leaving this logic here for safety.
    */
    cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
    if (cacheRemaining == 0) {
        sha1_update_block(ctx, ctx->cache);
    }

    /* Now we need to write a byte with the most significant bit set (0x80). */
    ctx->cache[ctx->cacheLen] = 0x80;
    ctx->cacheLen += 1;

    /* If there isn't enough room for 8 bytes we need to padd with zeroes and get the block processed. */
    cacheRemaining = sizeof(ctx->cache) - ctx->cacheLen;
    if (cacheRemaining < 8) {
        sha1_zero_memory(ctx->cache + ctx->cacheLen, cacheRemaining);
        sha1_update_block(ctx, ctx->cache);
        cacheRemaining = sizeof(ctx->cache);
    }
    
    /* Now we need to fill the buffer with zeros until we've filled 56 bytes (8 bytes left over for the length). */
    sha1_zero_memory(ctx->cache + ctx->cacheLen, cacheRemaining - 8);

    szLo = (unsigned int)(((ctx->sz >>  0) & 0xFFFFFFFF) << 3);
    szHi = (unsigned int)(((ctx->sz >> 32) & 0xFFFFFFFF) << 3);
    ctx->cache[56] = (unsigned char)((szHi >> 24) & 0xFF);
    ctx->cache[57] = (unsigned char)((szHi >> 16) & 0xFF);
    ctx->cache[58] = (unsigned char)((szHi >>  8) & 0xFF);
    ctx->cache[59] = (unsigned char)((szHi >>  0) & 0xFF);
    ctx->cache[60] = (unsigned char)((szLo >> 24) & 0xFF);
    ctx->cache[61] = (unsigned char)((szLo >> 16) & 0xFF);
    ctx->cache[62] = (unsigned char)((szLo >>  8) & 0xFF);
    ctx->cache[63] = (unsigned char)((szLo >>  0) & 0xFF);
    sha1_update_block(ctx, ctx->cache);

    /* Now write out the digest. */
    digest[ 0] = (unsigned char)(ctx->h[0] >> 24); digest[ 1] = (unsigned char)(ctx->h[0] >> 16); digest[ 2] = (unsigned char)(ctx->h[0] >> 8); digest[ 3] = (unsigned char)(ctx->h[0] >> 0);
    digest[ 4] = (unsigned char)(ctx->h[1] >> 24); digest[ 5] = (unsigned char)(ctx->h[1] >> 16); digest[ 6] = (unsigned char)(ctx->h[1] >> 8); digest[ 7] = (unsigned char)(ctx->h[1] >> 0);
    digest[ 8] = (unsigned char)(ctx->h[2] >> 24); digest[ 9] = (unsigned char)(ctx->h[2] >> 16); digest[10] = (unsigned char)(ctx->h[2] >> 8); digest[11] = (unsigned char)(ctx->h[2] >> 0);
    digest[12] = (unsigned char)(ctx->h[3] >> 24); digest[13] = (unsigned char)(ctx->h[3] >> 16); digest[14] = (unsigned char)(ctx->h[3] >> 8); digest[15] = (unsigned char)(ctx->h[3] >> 0);
    digest[16] = (unsigned char)(ctx->h[4] >> 24); digest[17] = (unsigned char)(ctx->h[4] >> 16); digest[18] = (unsigned char)(ctx->h[4] >> 8); digest[19] = (unsigned char)(ctx->h[4] >> 0);
}

SHA1_API void sha1(unsigned char* digest, const void* src, size_t sz)
{
    sha1_context ctx;
    sha1_init(&ctx);
    {
        sha1_update(&ctx, src, sz);
    }
    sha1_finalize(&ctx, digest);
}


static void sha1_format_byte(char* dst, unsigned char byte)
{
    const char* hex = "0123456789abcdef";
    dst[0] = hex[(byte & 0xF0) >> 4];
    dst[1] = hex[(byte & 0x0F)     ];
}

SHA1_API void sha1_format(char* dst, size_t dstCap, const unsigned char* hash)
{
    size_t i;

    if (dst == NULL) {
        return;
    }

    if (dstCap < SHA1_SIZE_FORMATTED) {
        if (dstCap > 0) {
            dst[0] = '\0';
        }

        return;
    }

    for (i = 0; i < SHA1_SIZE; i += 1) {
        sha1_format_byte(dst + (i*2), hash[i]);
    }

    /* Always null terminate. */
    dst[SHA1_SIZE_FORMATTED-1] = '\0';
}
#endif  /* sha1_c */
#endif  /* SHA1_IMPLEMENTATION */

/*
This software is available as a choice of the following licenses. Choose
whichever you prefer.

===============================================================================
ALTERNATIVE 1 - Public Domain (www.unlicense.org)
===============================================================================
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

In jurisdictions that recognize copyright laws, the author or authors of this
software dedicate any and all copyright interest in the software to the public
domain. We make this dedication for the benefit of the public at large and to
the detriment of our heirs and successors. We intend this dedication to be an
overt act of relinquishment in perpetuity of all present and future rights to
this software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>

===============================================================================
ALTERNATIVE 2 - MIT No Attribution
===============================================================================
Copyright 2022 David Reid

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
