mcu-csiphash-2-4
===================================================================================================

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

# Testing

# License

This code is released under the [MIT license](LICENSE).
