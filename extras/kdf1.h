/*
 * kdf1.h
 * Simple semi-KDF1 based on mcu-csiphash-2-4 SipHash implementation
 * Copyright (c) 2019 Michał Getka
 *
 * This function implements a sort of ISO18033 KDF1. The derived key length is
 * limited to 1023 bytes, and the shared secret is passed as siphash key, which
 * is not strictly what ISO standard suggests.
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
 */
#ifndef _KDF1_SIPHASH_H
#define _KDF1_SIPHASH_H

#include "siphash.h"
#include "stdio.h"
#include <stdlib.h>
#include <errno.h>

int kdf1(uint8_t *derived_key, const size_t derived_key_length,
    const uint8_t *info, const size_t info_len,
    const uint8_t *hash_key);

#endif
