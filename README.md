mcu-csiphash-2-4
===================================================================================================

[![Build Status](https://travis-ci.com/mgetka/mcu-csiphash-2-4.svg?branch=master)](https://travis-ci.com/mgetka/mcu-csiphash-2-4)

> SipHash is a family of pseudorandom functions (a.k.a. keyed hash functions) optimized for speed on
> short messages. 
> 
> Target applications include network traffic authentication and defense against hash-flooding DoS
> attacks. 
> 
> SipHash is secure, fast, and simple (for real):
>  * SipHash is simpler and faster than previous cryptographic algorithms (e.g. MACs based on universal
>    hashing)
>  * SipHash is competitive in performance with insecure non-cryptographic algorithms (e.g.
>    MurmurHash)
> 
> ~ [SipHash: a fast short-input PRF](https://131002.net/siphash/)

The library implements SipHash PRF for C. The implementation does not utilize 64-bit integer
arithmetics, thus it can be used in projects for small microcontrollers.

Implemented algorithm version uses 128-bit key to produce 64-bit hash of the provided data of
arbitrary length.

This library is strongly inspired by the [SipHash_2_4](http://www.forward.com.au/pfod/SipHashLibrary/)
library for 8bit Atmel processors authored by Matthew Ford. Actually, all the core logic of the
SipHash algorithm is sourced from there. The following is the copyright disclosure of the
SipHash_2_4 library author

```
(c)2013 Forward Computing and Control Pty. Ltd. 
www.forward.com.au
This code may be freely used for both private and commercial use.
Provide this copyright is maintained.
```

# Usage

```c
#include "siphash.h"

void siphash(uint8_t *hash,
             const uint8_t *data,
             const size_t len,
             const uint8_t *key)
```

Calculated hash of provided `data` will be stored in `hash`. Length of the data is passed as `len`.
Hash is calculated under the `key` provided as 16 element array of `uint8_t` type. Calculated hash
is stored in little-endian order.

Simple example of using the library is provided in `src/example.c`.

```c
#include "siphash.h"
#include <string.h>
#include <stdio.h>

void hexdump(const uint8_t * data, const size_t len) {
    unsigned int i;
    for (i = 0; i < len; i++)
        printf("0x%02x ",data[i]);
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
```

The example can be compiled by invoking
```
$ make example
```

# Testing

To perform the tests, run
```
$ make test
```

# License

This code is released under the [MIT license](LICENSE).
