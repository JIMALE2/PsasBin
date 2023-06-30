#ifndef PSASPIN_H_
#define PSASPIN_H_

#include <stdint.h>

#include "word.h"

typedef struct {
  word_t v0, v1, v2, v3, v4;
} state_t;

void PSASPIN_aeadinit(state_t* s, const uint8_t* npub, const uint8_t* k);
void PSASPIN_adata(state_t* s, const uint8_t* ad, uint64_t adlen,uint64_t crt);
void PSASPIN_adata_last(state_t* s, const uint8_t* ad, uint64_t adlen,uint64_t ctr );
//void PSASPIN_encrypt_first(state_t* s, uint8_t* c, const uint8_t* m, uint64_t mlen, const uint8_t* smn, unsigned long long adlen);
void PSASPIN_encrypt(state_t* s, uint8_t* c, const uint8_t* m, uint64_t mlen);
void PSASPIN_encrypt_last(state_t* s, uint8_t* c, const uint8_t* m, uint64_t mlen);
//void PSASPIN_decrypt_first(state_t* s, uint8_t* m, const uint8_t* c, uint64_t clen);
void PSASPIN_decrypt(state_t* s, uint8_t* m, const uint8_t* c, uint64_t clen);
void PSASPIN_decrypt_last(state_t* s, uint8_t* m, const uint8_t* c, uint64_t clen);
void PSASPIN_final(state_t* s, const uint8_t* k);

#endif /* PSASPIN_H */
