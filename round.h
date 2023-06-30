#ifndef ROUND_H_
#define ROUND_H_

#include "PSASPIN.h"
//#include "printstate.h"

forceinline void KINIT(word_t* K0, word_t* K1, word_t* K2) {
  *K0 = WORD_T(0);
  *K1 = WORD_T(0);
  *K2 = WORD_T(0);
}

forceinline void PINIT(state_t* s) {
  s->v0 = WORD_T(0);
  s->v1 = WORD_T(0);
  s->v2 = WORD_T(0);
  s->v3 = WORD_T(0);
  s->v4 = WORD_T(0);
}

forceinline void ROUND(state_t* s, word_t C) {
  state_t t;
  /* round constant */
  s->v2 = XOR(s->v2, C);
  /* s-box layer */
  s->v0 = XOR(s->v0, s->v4);
  s->v4 = XOR(s->v4, s->v3);
  s->v2 = XOR(s->v2, s->v1);
  t.v0 = XOR(s->v0, AND(NOT(s->v1), s->v2));
  t.v2 = XOR(s->v2, AND(NOT(s->v3), s->v4));
  t.v4 = XOR(s->v4, AND(NOT(s->v0), s->v1));
  t.v1 = XOR(s->v1, AND(NOT(s->v2), s->v3));
  t.v3 = XOR(s->v3, AND(NOT(s->v4), s->v0));
  t.v1 = XOR(t.v1, t.v0);
  t.v3 = XOR(t.v3, t.v2);
  t.v0 = XOR(t.v0, t.v4);
  /* linear layer */
  s->v2 = XOR(t.v2, ROT(t.v2, 6 - 1));
  s->v3 = XOR(t.v3, ROT(t.v3, 17 - 10));
  s->v4 = XOR(t.v4, ROT(t.v4, 41 - 7));
  s->v0 = XOR(t.v0, ROT(t.v0, 28 - 19));
  s->v1 = XOR(t.v1, ROT(t.v1, 61 - 39));
  s->v2 = XOR(t.v2, ROT(s->v2, 1));
  s->v3 = XOR(t.v3, ROT(s->v3, 10));
  s->v4 = XOR(t.v4, ROT(s->v4, 7));
  s->v0 = XOR(t.v0, ROT(s->v0, 19));
  s->v1 = XOR(t.v1, ROT(s->v1, 39));
  s->v2 = NOT(s->v2);
  //printstate(" round output", s);
}

#endif /* ROUND_H_ */
