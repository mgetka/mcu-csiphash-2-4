/*
 * kdf1.c
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

#include "kdf1.h"

int kdf1(uint8_t *derived_key, const size_t derived_key_length,
    const uint8_t *info, const size_t info_len,
    const uint8_t *hash_key) {
    
    uint8_t hash[8], *buffer, counter = 0;
    size_t offset = 0;
    
    /* 
     * To avoid troubles with endianness we limit maximum derived
     * key length to 1023 bytes and operate on a single byte counter.
     */
    if (derived_key_length > 1023) return -EINVAL;
    
    /* We don't know in advance how long is the hash input so malloc. */
    buffer = malloc(4 + info_len);
    if (!buffer) return -ENOMEM;
    
    /* Populate hash input buffer with provided info. */
    memcpy(buffer + 4, info, info_len);
    
    do {
        
        /*
         * As per ISO18033, the counter hashed string should have the form of
         * 
         *      Z || Counter || [OtherInfo]
         * 
         * where Z is the shared secret, four bytes Counter is incremented in 
         * each loop, and OtherInfo, is, uhm... other info. To be compliant with
         * the standard, counter should be represented in big-endian. So our signle
         * byte counter value is placed as a third element of the vector.
         */
        buffer[3] = counter;
        
        /*
         * In the standard implementation, the shared secret should be included at
         * the beginning of the hashed buffer. Given that siphash is a keyed hash,
         * we utilize the 128bit shared secret as a hash key. Due to this inconsistency,
         * it can be argued that this implementation is not KDF1 in the strict sense.
         * 
         * I won't argue with that.
         */
        siphash(hash, (const uint8_t *) buffer, 4 + info_len, hash_key);
        
        /* Don't copy too much */
        if (offset + 8 > derived_key_length) {
            memcpy(derived_key + offset, hash, derived_key_length - offset);
        } else {
            memcpy(derived_key + offset, hash, 8);
        }
        
        offset += 8;
        counter++;
        
    }
    while (offset < derived_key_length);
    
    /* Free the previously allocated memory. */
    free(buffer);
    
}
