/*
 * siphash-2-4.c
 * SipHash implementation for pre-C99 compilers
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
#ifndef _SIPHASH_2_4_H
#define _SIPHASH_2_4_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

void siphash(const uint8_t *date, const size_t len, const uint8_t *key, uint8_t *hash);

#endif
