#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#include <stdint.h>
#include "api.h"
#include "PSASPIN.h"
#include "config.h"
#include "round.h"

#define PSASPIN_128A_KEYBYTES 16
#define PSASPIN_128A_RATE 16
#define PSASPIN_128A_PB_ROUNDS 8

#define PSASPIN_128A_IV WORD_T(0x80800c0800000000ull)

#define START(n) ((3 + (n)) << 4 | (12 - (n)))
#define RC(c) WORD_T(c)

forceinline void P8ROUNDS(state_t* s) {
  ROUND(s, RC(0xb4));
  ROUND(s, RC(0xa5));
  ROUND(s, RC(0x96));
  ROUND(s, RC(0x87));
  ROUND(s, RC(0x78));
  ROUND(s, RC(0x69));
  ROUND(s, RC(0x5a));
  ROUND(s, RC(0x4b));
}

forceinline void PROUNDS(state_t* s, int nr) {
  for (int i = START(nr); i > 0x4a; i -= 0x0f) ROUND(s, RC(i));
}

#if PSASPIN_INLINE_PERM && PSASPIN_UNROLL_LOOPS

forceinline void P(state_t* s, int nr) {
  P8ROUNDS(s);
  }

#elif !PSASPIN_INLINE_PERM && PSASPIN_UNROLL_LOOPS

void P8(state_t* s);

forceinline void P(state_t* s, int nr) {
  P8(s);
  }

#elif PSASPIN_INLINE_PERM && !PSASPIN_UNROLL_LOOPS

forceinline void P(state_t* s, int nr) { PROUNDS(s, nr); }

#else /* !PSASPIN_INLINE_PERM && !PSASPIN_UNROLL_LOOPS */

void P(state_t* s, int nr);

#endif

#endif /* PERMUTATIONS_H_ */
