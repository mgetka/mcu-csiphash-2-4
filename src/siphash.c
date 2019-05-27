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

#define __XOR64(v,v1) {                                     \
    for (int i=0; i<8; i++) {                               \
        v[i] ^= v1[i];                                      \
    }                                                       \
}

void rotl64_16(uint8_t *v) {
    uint8_t v0 = v[0];
    uint8_t v1 = v[1];
    for (int i=0; i<6; i++) {
        v[i] = v[i+2];
    }
    v[6] = v0;
    v[7] = v1;
}

#define __ROTL64_16(v) {                                    \
    uint8_t v0 = v[0];                                      \
    uint8_t v1 = v[1];                                      \
    for (int i=0; i<6; i++) {                               \
        v[i] = v[i+2];                                      \
    }                                                       \
    v[6] = v0;                                              \
    v[7] = v1;                                              \
}

#define __ROTL64_32(v) {                                    \
    uint8_t vTemp;                                          \
    for (int i=0; i<4; i++) {                               \
        vTemp = v[i];                                       \
        v[i] = v[i+4];                                      \
        v[i+4]=vTemp;                                       \
    }                                                       \
}

void reverse64(uint8_t *x) {
    uint8_t xTemp;
    for (int i=0; i<4; i++) {
        xTemp = x[i];
        x[i] = x[7-i];
        x[7-i]=xTemp;
    }
}

#define __ADD64(v, s) {                                     \
    uint16_t carry = 0;                                     \
    for (int i=7; i>=0; i--) {                              \
        carry += v[i];                                      \
        carry += s[i];                                      \
        v[i] = carry;                                       \
        carry = carry>>8;                                   \
    }                                                       \
}

#define __ROTL64_xBITS(v,x) {                               \
    uint8_t v0 = (v)[0];                                    \
    for (int i=0; i<7; i++) {                               \
        (v)[i] = ((v)[i]<<(x)) | ((v)[i+1]>>(8-(x)));       \
    }                                                       \
    (v)[7] =  ((v)[7]<<(x)) | (v0>>(8-(x)));                \
}

#define __ROTR64_xBITS(v,x) {                               \
    uint8_t v7 = (v)[7];                                    \
    for (int i=7; i>0; i--) {                               \
        (v)[i] = ((v)[i]>>(x)) | ((v)[i-1]<<(8-(x)));       \
    }                                                       \
    (v)[0] =  ((v)[0]>>(x)) | (v7<<(8-(x)));                \
}


#define __ROL_17BITS(v) {                                   \
    rotl64_16(v);                                           \
    __ROTL64_xBITS(v,1);                                    \
}

#define __ROL_21BITS(v) {                                   \
    rotl64_16(v);                                           \
    __ROTL64_xBITS(v,5);                                    \
}

#define __ROL_13BITS(v) {                                   \
    rotl64_16(v);                                           \
    __ROTR64_xBITS(v,3);                                    \
}

#define __SIPHASH_ROUND() {                                 \
    __ADD64(v0,v1);                                         \
    __ADD64(v2,v3);                                         \
    __ROL_13BITS(v1);                                       \
    __ROTL64_16(v3);                                        \
                                                            \
    __XOR64(v1, v0);                                        \
    __XOR64(v3, v2);                                        \
    __ROTL64_32(v0);                                        \
                                                            \
    __ADD64(v2, v1);                                        \
    __ADD64(v0, v3);                                        \
    __ROL_17BITS(v1);                                       \
    __ROL_21BITS(v3);                                       \
                                                            \
    __XOR64(v1, v2);                                        \
    __XOR64(v3, v0);                                        \
    __ROTL64_32(v2);                                        \
}

#define __UPDATE_HASH(c) {                                  \
    msg_byte_counter++;                                     \
    m[m_idx--] = c;                                         \
    if (m_idx < 0) {                                        \
        m_idx = 7;                                          \
        __XOR64(v3, m);                                     \
        __SIPHASH_ROUND();                                  \
        __SIPHASH_ROUND();                                  \
        __XOR64(v0, m);                                     \
    }                                                       \
}

void siphash(uint8_t *hash, const uint8_t *data, const size_t len, const uint8_t *key) {
    
    uint8_t v0[] = {0x73, 0x6f, 0x6d, 0x65, 0x70, 0x73, 0x65, 0x75};
    uint8_t v1[] = {0x64, 0x6f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d};
    uint8_t v2[] = {0x6c, 0x79, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61};
    uint8_t v3[] = {0x74, 0x65, 0x64, 0x62, 0x79, 0x74, 0x65, 0x73};
    uint8_t m[8], msg_byte_counter;
    int8_t m_idx;
    unsigned int i;
    
    memcpy(m, key, 8);
    reverse64(m);
    __XOR64(v0, m);
    __XOR64(v2, m);
    
    memcpy(m, key+8, 8);
    reverse64(m);
    __XOR64(v1, m);
    __XOR64(v3, m);
    
    m_idx = 7;
    msg_byte_counter = 0;
    
    for (i = 0; i<len; i++) __UPDATE_HASH(data[i]);

    uint8_t msgLen = msg_byte_counter;

    while (m_idx > 0) __UPDATE_HASH(0);
    
    __UPDATE_HASH(msgLen);
    
    v2[7] ^= 0xff;
    __SIPHASH_ROUND();
    __SIPHASH_ROUND();
    __SIPHASH_ROUND();
    __SIPHASH_ROUND();
    
    __XOR64(v0, v1);
	__XOR64(v0, v2);
	__XOR64(v0, v3);
    
    memcpy(hash, v0, 8);
    
}