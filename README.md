# Solovay–Strassen

This is a small C17 demonstration of the Solovay–Strassen probabilistic
primality test. It generates two distinct primes, constructs a toy RSA
modulus, and shows the private exponents obtained with both Euler's totient
`phi(n)` and Carmichael's function `lambda(n)`.

The default run uses two 24-bit primes and 50 Solovay–Strassen rounds:

```sh
make
./ss-rsa-keys
```

Prime size, test rounds, and the random seed are configurable:

```sh
./ss-rsa-keys --bits 28 --rounds 64
./ss-rsa-keys --seed 1
./ss-rsa-keys --help
```

Run the built-in deterministic tests with:

```sh
make test
```

## Implementation notes

The program:

- produces odd candidates with exactly the requested bit width;
- samples Solovay–Strassen witnesses without modulo bias;
- avoids overflowing multiplication in modular arithmetic;
- guarantees that `p` and `q` are different;
- seeds its SplitMix64 generator from the operating system, while `--seed`
  permits repeatable tests and benchmarks; and
- builds with strict C17 warnings enabled.

This is an educational example, **not a cryptographic key generator**.
SplitMix64 is not a cryptographically secure random-number generator, the
default primes are trivially small, and a probable-prime test is not a
substitute for a reviewed cryptographic library. Use a maintained library and
an operating-system CSPRNG for real keys.

## Benchmark

The benchmark mode generates a batch without printing each key, measures it
with a monotonic clock, and emits CSV containing elapsed seconds and keypairs
per second. For example:

```sh
./ss-rsa-keys --bits 24 --rounds 50 --seed 1 --benchmark 100000
```

I measured it with [Pilot](https://github.com/darrelllong/pilot-bench) 0.14
(`a6e6e7739bb6`) using this command:

```sh
../pilot-bench/build/cli/bench run_program \
  --preset quick --confidence-level 0.95 --ci-perc 0.05 \
  --min-sample-size 30 --session-limit 180 \
  --pi 'keypair throughput,keypairs/s,1,1,1' \
  -- ./ss-rsa-keys --bits 24 --rounds 50 --seed 1 \
     --benchmark 100000
```

On a MacBook Neo (`Mac17,5`) with an Apple A18 Pro (6 cores, 8 GB RAM),
macOS 27.0.1, and Apple clang 21.0.0 at `-O3`, Pilot stopped after 47 samples
and 104.9 seconds. The harmonic-mean throughput was **44,903.6 keypairs/s**,
with a 95% confidence interval of **43,819.9–46,042.2 keypairs/s** (width
2,222.3 keypairs/s, or 4.95% of the mean).

Each sample generated 100,000 complete keypairs from a fixed seed using the
default 24-bit prime size and 50 Solovay–Strassen rounds. The timing excludes
process startup and output formatting. Results will vary with hardware,
compiler, thermals, and system load.
