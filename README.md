# Solovay-Strassen
An example of
Solovay–Strassen primality testing, and we generate RSA keys as a
way of showing that it works.
Both Euler's 𝜑 and Carmichael's 𝜆 varieties are produced.

This example only uses 64-bit numbers but it can be easily
transformed (but it is ugly) to `mpz_t` using the Gnu multi-precision library.
