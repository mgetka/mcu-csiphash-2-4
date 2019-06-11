Simple semi-KDF1 based on mcu-csiphash-2-4 w/o dynamic memory allocation
-----------------------------

The function implements a sort of ISO18033 KDF1. The derived key length is
limited to 1023 bytes, and the shared secret is passed as siphash key, which
is not strictly what ISO standard suggests.

This implementation utilizes only statically allocated buffers.
