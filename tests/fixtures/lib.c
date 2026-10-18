// A library whose two builds differ by inserted functions and changed
// constants, so that branch targets, relocated pointers and data references
// all move between them. Build the newer one with -DNEWER.

#include <stdint.h>

typedef uint32_t (*step_fn)(uint32_t);

#define NAME_COUNT 16
extern const char *const names[NAME_COUNT];

#ifdef NEWER
#define SALT 0x9E3779B9u
#else
#define SALT 0x85EBCA6Bu
#endif

#define STEP(n)                                                    \
    __attribute__((noinline)) uint32_t step##n(uint32_t x) {       \
        if (x & (1u << ((n) % 31))) {                              \
            x = x * SALT + (n);                                    \
        } else {                                                   \
            x ^= x >> ((n) % 7 + 1);                               \
        }                                                          \
        return x + (uint32_t)names[(n) % NAME_COUNT][(n) % 3];     \
    }

#define STEPS(t)                                                   \
    STEP(t##0) STEP(t##1) STEP(t##2) STEP(t##3) STEP(t##4)         \
    STEP(t##5) STEP(t##6) STEP(t##7) STEP(t##8) STEP(t##9)

#define REFS(t)                                                    \
    step##t##0, step##t##1, step##t##2, step##t##3, step##t##4,    \
    step##t##5, step##t##6, step##t##7, step##t##8, step##t##9,

#ifdef NEWER
STEPS(10)
STEPS(11)
#endif
STEP(0) STEP(1) STEP(2) STEP(3) STEP(4)
STEP(5) STEP(6) STEP(7) STEP(8) STEP(9)
STEPS(1)
STEPS(2)
STEPS(3)
STEPS(4)
STEPS(5)
STEPS(6)
STEPS(7)
STEPS(8)
STEPS(9)

const step_fn steps[] = {
#ifdef NEWER
    REFS(10)
    REFS(11)
#endif
    step0, step1, step2, step3, step4, step5, step6, step7, step8, step9,
    REFS(1) REFS(2) REFS(3) REFS(4) REFS(5) REFS(6) REFS(7) REFS(8) REFS(9)
};

const char *const names[NAME_COUNT] = {
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    "india", "juliett", "kilo", "lima", "mike", "november", "oscar",
#ifdef NEWER
    "quebec",
#else
    "papa",
#endif
};

#define CALLS(t)                                                   \
    x = step##t##0(x); x = step##t##1(x); x = step##t##2(x);       \
    x = step##t##3(x); x = step##t##4(x); x = step##t##5(x);       \
    x = step##t##6(x); x = step##t##7(x); x = step##t##8(x);       \
    x = step##t##9(x);

// A loop on a single bit whose body is longer than a short THUMB2
// conditional branch reaches, so AArch64 loops with TBNZ and THUMB2 with a
// 32-bit conditional branch.
uint32_t chain(uint32_t x) {
    do {
        CALLS(1) CALLS(2) CALLS(3) CALLS(4) CALLS(5) CALLS(6) CALLS(7)
    } while (x & 0x40);
    return x;
}

uint32_t run(uint32_t seed, unsigned rounds) {
    uint32_t x = seed;
    for (unsigned i = 0; i < rounds; i++) {
        x = steps[(x + i) % (sizeof(steps) / sizeof(steps[0]))](x);
        switch (x % 8) {
        case 0: x = step3(x); break;
        case 1: x = step17(x); break;
        case 2: x = step29(x); break;
        case 3: x = step42(x); break;
        case 4: x = step58(x); break;
        case 5: x = step63(x); break;
        case 6: x = step77(x); break;
        default: x = step91(x); break;
        }
        if (x == 0) {
            break;
        }
    }
    return x;
}
