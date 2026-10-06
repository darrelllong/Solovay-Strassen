#define _DEFAULT_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif
#include <time.h>
#include <unistd.h>

enum {
  DEFAULT_BITS = 24,
  DEFAULT_ROUNDS = 50,
  MIN_BITS = 10,
  MAX_BITS = 31
};

static_assert(MAX_BITS * 2 < 63,
              "RSA arithmetic must fit in a signed 64-bit integer");

typedef struct {
  uint64_t state;
} rng_t;

typedef struct {
  uint64_t p;
  uint64_t q;
  uint64_t n;
  uint64_t phi;
  uint64_t lambda;
  uint64_t e_phi;
  uint64_t d_phi;
  uint64_t e_lambda;
  uint64_t d_lambda;
} rsa_keys_t;

/* Keep benchmark work observable to the optimizer. */
static volatile uint64_t benchmark_sink;

/* SplitMix64 is reproducible, but not suitable for cryptography. */
static uint64_t rng_next(rng_t *rng) {
  uint64_t z = (rng->state += UINT64_C(0x9e3779b97f4a7c15));
  z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
  return z ^ (z >> 31);
}

static void rng_seed_from_system(rng_t *rng) {
  uint64_t seed = 0;
  if (getentropy(&seed, sizeof(seed)) != 0) {
    struct timespec now = {};
    (void)timespec_get(&now, TIME_UTC);
    seed = ((uint64_t)now.tv_sec << 32) ^ (uint64_t)now.tv_nsec ^
           (uint64_t)getpid();
  }
  rng->state = seed;
}

/* Rejection sampling avoids modulo bias. */
static uint64_t rng_below(rng_t *rng, uint64_t bound) {
  const uint64_t threshold = (uint64_t)(-bound) % bound;
  uint64_t value;

  do {
    value = rng_next(rng);
  } while (value < threshold);
  return value % bound;
}

static uint64_t add_mod(uint64_t a, uint64_t b, uint64_t modulus) {
  return a >= modulus - b ? a - (modulus - b) : a + b;
}

/* Double-and-add avoids overflowing a * b. */
static uint64_t multiply_mod(uint64_t a, uint64_t b, uint64_t modulus) {
  uint64_t result = 0;

  a %= modulus;
  b %= modulus;
  if (a == 0 || b <= UINT64_MAX / a) {
    return (a * b) % modulus;
  }

  while (b != 0) {
    if ((b & 1U) != 0) {
      result = add_mod(result, a, modulus);
    }
    b >>= 1;
    if (b != 0) {
      a = add_mod(a, a, modulus);
    }
  }
  return result;
}

static uint64_t power_mod(uint64_t base, uint64_t exponent,
                          uint64_t modulus) {
  uint64_t result = 1 % modulus;

  base %= modulus;
  while (exponent != 0) {
    if ((exponent & 1U) != 0) {
      result = multiply_mod(result, base, modulus);
    }
    exponent >>= 1;
    if (exponent != 0) {
      base = multiply_mod(base, base, modulus);
    }
  }
  return result;
}

static int jacobi_symbol(uint64_t numerator, uint64_t denominator) {
  int sign = 1;

  if (denominator == 0 || (denominator & 1U) == 0) {
    return 0;
  }
  numerator %= denominator;
  while (numerator != 0) {
    while ((numerator & 1U) == 0) {
      numerator >>= 1;
      const uint64_t residue = denominator & 7U;
      if (residue == 3 || residue == 5) {
        sign = -sign;
      }
    }

    const uint64_t swap = numerator;
    numerator = denominator;
    denominator = swap;
    if ((numerator & 3U) == 3 && (denominator & 3U) == 3) {
      sign = -sign;
    }
    numerator %= denominator;
  }
  return denominator == 1 ? sign : 0;
}

static bool is_probable_prime(uint64_t candidate, uint32_t rounds,
                              rng_t *rng) {
  static const uint32_t small_primes[] = {
      2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};

  if (candidate < 2) {
    return false;
  }
  for (size_t i = 0; i < sizeof small_primes / sizeof *small_primes; ++i) {
    if (candidate == small_primes[i]) {
      return true;
    }
    if (candidate % small_primes[i] == 0) {
      return false;
    }
  }

  for (uint32_t i = 0; i < rounds; ++i) {
    const uint64_t witness = 2 + rng_below(rng, candidate - 3);
    const int jacobi = jacobi_symbol(witness, candidate);
    const uint64_t expected = jacobi < 0 ? candidate - 1 : (uint64_t)jacobi;

    if (jacobi == 0 ||
        power_mod(witness, (candidate - 1) / 2, candidate) != expected) {
      return false;
    }
  }
  return true;
}

static uint64_t random_prime(uint32_t bits, uint32_t rounds, rng_t *rng) {
  const uint64_t mask = (UINT64_C(1) << bits) - 1;
  const uint64_t high_bit = UINT64_C(1) << (bits - 1);

  for (;;) {
    const uint64_t candidate = (rng_next(rng) & mask) | high_bit | 1U;
    if (is_probable_prime(candidate, rounds, rng)) {
      return candidate;
    }
  }
}

static uint64_t greatest_common_divisor(uint64_t a, uint64_t b) {
  while (b != 0) {
    const uint64_t remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}

static uint64_t least_common_multiple(uint64_t a, uint64_t b) {
  return (a / greatest_common_divisor(a, b)) * b;
}

static uint64_t modular_inverse(uint64_t value, uint64_t modulus) {
  int64_t old_coefficient = 0;
  int64_t coefficient = 1;
  int64_t old_remainder = (int64_t)modulus;
  int64_t remainder = (int64_t)(value % modulus);

  while (remainder != 0) {
    const int64_t quotient = old_remainder / remainder;
    const int64_t next_remainder = old_remainder - quotient * remainder;
    const int64_t next_coefficient =
        old_coefficient - quotient * coefficient;

    old_remainder = remainder;
    remainder = next_remainder;
    old_coefficient = coefficient;
    coefficient = next_coefficient;
  }
  if (old_remainder != 1) {
    return 0;
  }
  if (old_coefficient < 0) {
    old_coefficient += (int64_t)modulus;
  }
  return (uint64_t)old_coefficient;
}

static uint64_t public_exponent(uint64_t modulus) {
  uint64_t exponent = 65537;

  while (greatest_common_divisor(exponent, modulus) != 1) {
    exponent += 2;
  }
  return exponent;
}

static double monotonic_seconds(void) {
  struct timespec now = {};

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
  return (double)now.tv_sec + (double)now.tv_nsec / 1'000'000'000.0;
}

static rsa_keys_t generate_keys(uint32_t bits, uint32_t rounds, rng_t *rng) {
  rsa_keys_t keys = {};

  keys.p = random_prime(bits, rounds, rng);
  do {
    keys.q = random_prime(bits, rounds, rng);
  } while (keys.q == keys.p);

  keys.n = keys.p * keys.q;
  keys.phi = (keys.p - 1) * (keys.q - 1);
  keys.lambda = least_common_multiple(keys.p - 1, keys.q - 1);
  keys.e_phi = public_exponent(keys.phi);
  keys.d_phi = modular_inverse(keys.e_phi, keys.phi);
  keys.e_lambda = public_exponent(keys.lambda);
  keys.d_lambda = modular_inverse(keys.e_lambda, keys.lambda);
  return keys;
}

static bool parse_u64(const char *text, uint64_t *value) {
  char *end = nullptr;

  if (text[0] == '-') {
    return false;
  }
  errno = 0;
  const uintmax_t parsed = strtoumax(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' || parsed > UINT64_MAX) {
    return false;
  }
  *value = (uint64_t)parsed;
  return true;
}

static void print_usage(const char *program) {
  printf("Usage: %s [--bits N] [--rounds N] [--seed N]\n", program);
  printf("       %s [options] --benchmark COUNT\n", program);
  printf("       %s --self-test\n", program);
  printf("\nDefaults: %d-bit primes and %d Solovay-Strassen rounds.\n",
         DEFAULT_BITS, DEFAULT_ROUNDS);
}

static bool run_self_tests(void) {
  rng_t rng = {UINT64_C(0x4d595df4d0f33173)};
  bool ok = true;

#define CHECK(expression)                                                       \
  do {                                                                          \
    if (!(expression)) {                                                        \
      fprintf(stderr, "self-test failed at line %d: %s\n", __LINE__,           \
              #expression);                                                     \
      ok = false;                                                               \
    }                                                                           \
  } while (false)

  CHECK(power_mod(4, 13, 497) == 445);
  CHECK(jacobi_symbol(1001, 9907) == -1);
  CHECK(jacobi_symbol(3, 15) == 0);
  CHECK(greatest_common_divisor(48, 18) == 6);
  CHECK(least_common_multiple(21, 6) == 42);
  CHECK(modular_inverse(17, 3120) == 2753);
  CHECK(is_probable_prime(41, 20, &rng));
  CHECK(is_probable_prime(65537, 20, &rng));
  CHECK(!is_probable_prime(1, 20, &rng));
  CHECK(!is_probable_prime(25, 20, &rng));
  CHECK(!is_probable_prime(561, 20, &rng));

  const rsa_keys_t keys = generate_keys(16, 20, &rng);
  CHECK(keys.p != keys.q);
  CHECK(keys.p >= (UINT64_C(1) << 15));
  CHECK(keys.q >= (UINT64_C(1) << 15));
  CHECK(multiply_mod(keys.e_phi, keys.d_phi, keys.phi) == 1);
  CHECK(multiply_mod(keys.e_lambda, keys.d_lambda, keys.lambda) == 1);
  CHECK(power_mod(power_mod(42, keys.e_lambda, keys.n), keys.d_lambda,
                  keys.n) == 42);

#undef CHECK

  if (ok) {
    puts("all self-tests passed");
  }
  return ok;
}

int main(int argc, char **argv) {
  uint32_t bits = DEFAULT_BITS;
  uint32_t rounds = DEFAULT_ROUNDS;
  uint64_t benchmark_count = 0;
  uint64_t seed = 0;
  bool seed_supplied = false;
  bool self_test = false;

  for (int i = 1; i < argc; ++i) {
    uint64_t parsed;

    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      print_usage(argv[0]);
      return EXIT_SUCCESS;
    }
    if (strcmp(argv[i], "--self-test") == 0) {
      self_test = true;
      continue;
    }
    if ((strcmp(argv[i], "--bits") == 0 ||
         strcmp(argv[i], "--rounds") == 0 ||
         strcmp(argv[i], "--seed") == 0 ||
         strcmp(argv[i], "--benchmark") == 0) &&
        i + 1 < argc && parse_u64(argv[i + 1], &parsed)) {
      if (strcmp(argv[i], "--bits") == 0) {
        if (parsed < MIN_BITS || parsed > MAX_BITS) {
          fprintf(stderr, "--bits must be between %d and %d\n", MIN_BITS,
                  MAX_BITS);
          return EXIT_FAILURE;
        }
        bits = (uint32_t)parsed;
      } else if (strcmp(argv[i], "--rounds") == 0) {
        if (parsed == 0 || parsed > UINT32_MAX) {
          fputs("--rounds must be between 1 and 4294967295\n", stderr);
          return EXIT_FAILURE;
        }
        rounds = (uint32_t)parsed;
      } else if (strcmp(argv[i], "--seed") == 0) {
        seed = parsed;
        seed_supplied = true;
      } else {
        if (parsed == 0) {
          fputs("--benchmark must be greater than zero\n", stderr);
          return EXIT_FAILURE;
        }
        benchmark_count = parsed;
      }
      ++i;
      continue;
    }
    fprintf(stderr, "invalid or incomplete option: %s\n", argv[i]);
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  if (self_test) {
    return run_self_tests() ? EXIT_SUCCESS : EXIT_FAILURE;
  }

  rng_t rng;
  if (seed_supplied) {
    rng.state = seed;
  } else {
    rng_seed_from_system(&rng);
  }

  if (benchmark_count != 0) {
    uint64_t checksum = 0;
    const double start = monotonic_seconds();
    for (uint64_t i = 0; i < benchmark_count; ++i) {
      const rsa_keys_t keys = generate_keys(bits, rounds, &rng);
      checksum ^= keys.n ^ keys.d_lambda;
    }
    const double elapsed = monotonic_seconds() - start;
    benchmark_sink = checksum;
    printf("%.9f,%.3f\n", elapsed, (double)benchmark_count / elapsed);
    return EXIT_SUCCESS;
  }

  const rsa_keys_t keys = generate_keys(bits, rounds, &rng);
  puts("Random RSA key demonstration");
  printf("p = %" PRIu64 ", q = %" PRIu64 ", n = %" PRIu64 "\n\n",
         keys.p, keys.q, keys.n);
  printf("phi = %" PRIu64 ", e = %" PRIu64 ", d = %" PRIu64 "\n",
         keys.phi, keys.e_phi, keys.d_phi);
  printf("e * d mod phi = %" PRIu64 "\n\n",
         multiply_mod(keys.e_phi, keys.d_phi, keys.phi));
  printf("lambda = %" PRIu64 ", e = %" PRIu64 ", d = %" PRIu64 "\n",
         keys.lambda, keys.e_lambda, keys.d_lambda);
  printf("e * d mod lambda = %" PRIu64 "\n\n",
         multiply_mod(keys.e_lambda, keys.d_lambda, keys.lambda));
  printf("phi / lambda = %" PRIu64 " / %" PRIu64 " = %" PRIu64 "\n",
         keys.phi, keys.lambda, keys.phi / keys.lambda);
  puts("\nEducational example only; these small keys and this RNG are not secure.");
  return EXIT_SUCCESS;
}
