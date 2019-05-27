/*
 * siphash-2-4.c
 * SipHash implementation for compilers w/o 64 bit arithmetics
 * Copyright (c) 2019 Michał Getka
 * 
 * Simple example of using the library
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

#include "siphash-2-4.h"
#include <string.h>
#include <stdio.h>

void hexdump(const uint8_t * data, const size_t len) {
    unsigned int i;
    for (i = 0; i < len; i++)
        printf("0x%x ",data[i]);
    printf("\n");
}

unsigned int main() {
    
    uint8_t hash[8];
    uint8_t key[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                     0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    char *data = "Hello world!";
    
    siphash(hash, (const uint8_t *) data, strlen(data), key);
    
    printf("Data:\t%s\n", data);
    printf("Key:\t"); hexdump(key, (size_t) 16);
    printf("Hash:\t"); hexdump(hash, (size_t) 8);
    
    return 0;
    
}