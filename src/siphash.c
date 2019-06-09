/*
 * siphash.c
 * SipHash implementation for compilers w/o 64 bit arithmetics
 * Copyright (c) 2019 Michał Getka
 * 
 * SipHash is a family of pseudorandom functions (a.k.a. keyed hash functions) optimized for speed on short messages. 
 * Target applications include network traffic authentication and defense against hash-flooding DoS attacks. 
 *  - https://131002.net/siphash/
 *
 * The library implements siphash PRF. The implementation does not utilize 64-bit integer arithmetics.
 * 
 */

/*  
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * This library is strongly inspired by the SipHash_2_4 library for 8bit Atmel processors authored by Matthew Ford.
 * Actually, all the core logic of the siphash algorithm is sourced from there. The following is the copyright
 * disclosure of the SipHash_2_4 library author
 *
 * (c)2013 Forward Computing and Control Pty. Ltd. 
 * www.forward.com.au
 * This code may be freely used for both private and commercial use.
 * Provide this copyright is maintained.
 * 
 */

#include "siphash.h"

void _msh_rotl64_16(uint8_t *v) {
    uint8_t v0 = v[0];
    uint8_t v1 = v[1];
    int i;
    for (i = 0; i < 6; i++) {
        v[i] = v[i+2];
    }
    v[6] = v0;
    v[7] = v1;
}

void _msh_reverse64(uint8_t *x) {
    uint8_t xTemp;
    int i;
    for (i = 0; i < 4; i++) {
        xTemp = x[i];
        x[i] = x[7-i];
        x[7-i]=xTemp;
    }
}

/*
 * The following macros require that in the scope of their execution the variable int _i is defined.
 */

#define _msh_XOR64(v,v1) {                                  \
    for (_i = 0; _i < 8; _i++) {                            \
        v[_i] ^= v1[_i];                                    \
    }                                                       \
}

#define _msh_ROTL64_16(v) {                                 \
    uint8_t v0 = v[0];                                      \
    uint8_t v1 = v[1];                                      \
    for (_i = 0; _i < 6; _i++) {                            \
        v[_i] = v[_i+2];                                    \
    }                                                       \
    v[6] = v0;                                              \
    v[7] = v1;                                              \
}

#define _msh_ROTL64_32(v) {                                 \
    uint8_t vTemp;                                          \
    for (_i = 0; _i < 4; _i++) {                            \
        vTemp = v[_i];                                      \
        v[_i] = v[_i+4];                                    \
        v[_i+4] = vTemp;                                    \
    }                                                       \
}

#define _msh_ADD64(v, s) {                                  \
    uint16_t carry = 0;                                     \
    for (_i = 7; _i >= 0; _i--) {                           \
        carry += v[_i];                                     \
        carry += s[_i];                                     \
        v[_i] = carry;                                      \
        carry = carry>>8;                                   \
    }                                                       \
}

#define _msh_ROTL64_xBITS(v,x) {                            \
    uint8_t v0 = (v)[0];                                    \
    for (_i = 0; _i < 7; _i++) {                            \
        (v)[_i] = ((v)[_i]<<(x)) | ((v)[_i+1]>>(8-(x)));    \
    }                                                       \
    (v)[7] =  ((v)[7]<<(x)) | (v0>>(8-(x)));                \
}

#define _msh_ROTR64_xBITS(v,x) {                            \
    uint8_t v7 = (v)[7];                                    \
    for (_i = 7; _i > 0; _i--) {                            \
        (v)[_i] = ((v)[_i]>>(x)) | ((v)[_i-1]<<(8-(x)));    \
    }                                                       \
    (v)[0] = ((v)[0]>>(x)) | (v7<<(8-(x)));                 \
}


#define _msh_ROL_17BITS(v) {                                \
    _msh_rotl64_16(v);                                      \
    _msh_ROTL64_xBITS(v,1);                                 \
}

#define _msh_ROL_21BITS(v) {                                \
    _msh_rotl64_16(v);                                      \
    _msh_ROTL64_xBITS(v,5);                                 \
}

#define _msh_ROL_13BITS(v) {                                \
    _msh_rotl64_16(v);                                      \
    _msh_ROTR64_xBITS(v,3);                                 \
}

#define _msh_SIPHASH_ROUND() {                              \
    _msh_ADD64(v0,v1);                                      \
    _msh_ADD64(v2,v3);                                      \
    _msh_ROL_13BITS(v1);                                    \
    _msh_ROTL64_16(v3);                                     \
                                                            \
    _msh_XOR64(v1, v0);                                     \
    _msh_XOR64(v3, v2);                                     \
    _msh_ROTL64_32(v0);                                     \
                                                            \
    _msh_ADD64(v2, v1);                                     \
    _msh_ADD64(v0, v3);                                     \
    _msh_ROL_17BITS(v1);                                    \
    _msh_ROL_21BITS(v3);                                    \
                                                            \
    _msh_XOR64(v1, v2);                                     \
    _msh_XOR64(v3, v0);                                     \
    _msh_ROTL64_32(v2);                                     \
}

#define _msh_UPDATE_HASH(c) {                               \
    msg_byte_counter++;                                     \
    m[m_idx--] = c;                                         \
    if (m_idx < 0) {                                        \
        m_idx = 7;                                          \
        _msh_XOR64(v3, m);                                  \
        _msh_SIPHASH_ROUND();                               \
        _msh_SIPHASH_ROUND();                               \
        _msh_XOR64(v0, m);                                  \
    }                                                       \
}

void siphash(uint8_t *hash, const uint8_t *data, const size_t len, const uint8_t *key) {
    
    uint8_t v0[] = {0x73, 0x6f, 0x6d, 0x65, 0x70, 0x73, 0x65, 0x75};
    uint8_t v1[] = {0x64, 0x6f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d};
    uint8_t v2[] = {0x6c, 0x79, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61};
    uint8_t v3[] = {0x74, 0x65, 0x64, 0x62, 0x79, 0x74, 0x65, 0x73};
    uint8_t m[8], msg_byte_counter;
    int8_t m_idx;
    int _i, i;
    
    memcpy(m, key, 8);
    _msh_reverse64(m);
    _msh_XOR64(v0, m);
    _msh_XOR64(v2, m);
    
    memcpy(m, key+8, 8);
    _msh_reverse64(m);
    _msh_XOR64(v1, m);
    _msh_XOR64(v3, m);
    
    m_idx = 7;
    msg_byte_counter = 0;
    
    for (i = 0; i < len; i++) _msh_UPDATE_HASH(data[i]);
    
    uint8_t msgLen = msg_byte_counter;
    
    while (m_idx > 0) _msh_UPDATE_HASH(0);
    
    _msh_UPDATE_HASH(msgLen);
    
    v2[7] ^= 0xff;
    _msh_SIPHASH_ROUND();
    _msh_SIPHASH_ROUND();
    _msh_SIPHASH_ROUND();
    _msh_SIPHASH_ROUND();
    
    _msh_XOR64(v0, v1);
    _msh_XOR64(v0, v2);
    _msh_XOR64(v0, v3);
    
    memcpy(hash, v0, 8);
    
    _msh_reverse64(hash);
    
}
