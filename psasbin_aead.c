#include "api.h"
#include "PSASPIN.h"
#include "crypto_aead.h"
#include "permutations.h"
#include<stdlib.h>
#include<stdio.h>
#include<math.h>
#include<stdint.h>
#include<time.h>
#include<string.h>
// suppress bogus warning when compiling with gcc 4.3
#if (__GNUC__ == 4 && __GNUC_MINOR__ == 3)
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif

// Declare globan variables

uint64_t lmlen=0;
uint64_t aadlen=0;
uint64_t nsslen=0;
uint8_t* mm=0;
uint8_t* aad=0;
uint8_t* cc=0;
uint64_t t1= 0;
uint64_t t2= 0;
// rekeying variables
const uint64_t min_poly  = 16385;//0b1000000000000001;    /* irreducible polinomial x^16 + 1 */
uint64_t mKey =0;
uint64_t N=0;
time_t t;
uint64_t sessionKeyA[]={0};
uint64_t sessionKeyB[]={0};
uint64_t maskVal[] ={0};
//end rekeyying variables


void print_test(unsigned char c, unsigned char* x, unsigned long long xlen) {
  unsigned long long i;
  printf("%c[%d]=", c, (int)xlen);
  for (i = 0; i < xlen; ++i) printf("%c", x[i]);
  printf("\n");
}

// the GF multilicaiton Function
uint64_t GFmult(uint64_t x, uint64_t y)
{
    uint64_t res = 0;
    for (; y; y >>= 1) {
        if (y & 1)
            res ^= x;
        if (x & 0x80)
            x = (x << 1) ^ min_poly;
        else
            x <<= 1;
    }
    return res;
}
// the parallel fresh rekeying function
uint64_t* PFRK (uint64_t masterKey, uint64_t rtoken){
uint16_t d =16;
int numofkeys=1;
while (numofkeys <= d)
{
srand((unsigned) time(&t));

for (int i=1; i<=d; i++)
{
    maskVal[i]^=rand();// randon mask values are generated
}
d=16;
//apply the mask values
// applied in a random order for shuffling
for (int i = 1; i<=d; i++)
{
// calculate the intermediate session keys
    sessionKeyA[i]^=masterKey^maskVal[i];
}
d=16;

    sessionKeyB[numofkeys] = GFmult(sessionKeyA[numofkeys],rtoken);
    
//remove the mask value
for (int i = 1; i<=d; i++)
{
    sessionKeyB[i]^=maskVal[i];
}
numofkeys++;

}
// produce the number of keys required
return sessionKeyB;
}


//void begin();
forceinline void PSASPIN_RETkey(word_t* K0, word_t* K1, word_t* K2,
                               const uint8_t* k) {
   KINIT(K0, K1, K2);
  
  //if (CRYPTO_KEYBYTES == 16) {
    *K1 = XOR(*K1, RET(k, 8));
    *K2 = XOR(*K2, RET(k + 8, 8));
  //}
  //printf ("Key rot ok");
}

/// initizalization
forceinline void PSASPIN_aeadinit(state_t* s, const uint8_t* npub,
                                const uint8_t* k) {
  /* RET nonce */
  word_t N0 = RET(npub, 8);
  word_t N1 = RET(npub + 8, 8);
  /* RET key */
  word_t K0, K1, K2;
  PSASPIN_RETkey(&K0, &K1, &K2, k);
  /* initialize */
  PINIT(s);
  
  s->v0 = XOR(s->v0, PSASPIN_128A_IV);
  s->v1 = XOR(s->v1, K1);
  s->v2 = XOR(s->v2, K2);
  s->v3 = XOR(s->v3, N0);
  s->v4 = XOR(s->v4, N1);
  P(s, 8);
  
  s->v3 = XOR(s->v3, K1);
  s->v4 = XOR(s->v4, K2);
  //printf ("Initialization done\n");
}

// process associated data
forceinline void PSASPIN_adata(state_t* s, const uint8_t* ad, uint64_t adlen, uint64_t ctr) {
    const int nr = 8;
  if (adlen) {
    /* full associated data blocks */
      s->v0^=ctr;
      s->v0 = XOR(s->v0, RET(ad, 8));
      s->v1 = XOR(s->v1, RET(ad + 8, 8));
      P(s, nr);
    //printf (" fuldata ad blocks\n");
  }
}

forceinline void PSASPIN_adata_last(state_t* s, const uint8_t* ad, uint64_t adlen,uint64_t ctr) { 
    /* final associated data block */
    const int nr = 8;
    ad=aad;
    adlen=aadlen;
    s->v0^=ctr;
    if (adlen){
    word_t* px = &s->v0;
    if (PSASPIN_AEAD_RATE == 16 && adlen >= 8) {
      s->v0 = XOR(s->v0, RET(ad, 8));
      px = &s->v1;
      ad += 8;
      adlen -= 8;
    }
    *px = XOR(*px, LPAD(adlen));
    if (adlen) *px = XOR(*px, RET(ad, adlen));
    P(s, nr);
  }
  /* domain separation */
  s->v4 = XOR(s->v4, WORD_T(1));
  //printf ("AD done last\n");
  
}

// encrypt message
forceinline void PSASPIN_encrypt_first(state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen, const uint8_t* smn,unsigned long long nseclen) {
  
  mlen=mlen;
  m=m;
  const int nr = 8;
  s->v0 = XOR(s->v0, RET(smn, 8));
  STORE(c, s->v0, 8);
  s->v1 = XOR(s->v1, RET(smn + 8, 8));
  STORE(c + 8, s->v1, 8);
    
  P(s, nr);
  // process the intermediate tags
  t1^= s->v3;
  t2^= s->v4;
   
  nsslen=nseclen;    //printf("nslen in encrypt first: %d", nsslen);
    //printf("Encrypt first separate\n");
   
    
  }

forceinline void PSASPIN_encrypt(state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen) {
  
  mlen=mlen;
  const int nr = 8;
  /* full plaintext blocks */
    s->v0 = XOR(s->v0, RET(m, 8));
    STORE(c, s->v0, 8);
    s->v1 = XOR(s->v1, RET(m + 8, 8));
      STORE(c + 8, s->v1, 8);
     
    P(s, nr);
    t1^= s->v3;
    t2^= s->v4;
    
    lmlen=mlen;
    //printf("Encrypt separate\n");
    
}
forceinline void PSASPIN_encrypt_last(state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen)                               {
 mlen=lmlen;
 c=cc;
 m=mm;
  /* final plaintext block */
   word_t* px = &s->v0;
  if (PSASPIN_AEAD_RATE == 16 && mlen >= 8) {
    s->v0 = XOR(s->v0, RET(m, 8));
    STORE(c, s->v0, 8);
    px = &s->v1;
    m += 8;
    c += 8;
    mlen -= 8;
  }
  *px = XOR(*px, LPAD(mlen));
  if (mlen) {
    *px = XOR(*px, RET(m, mlen));
    STORE(c, *px, mlen);
  }
  // process the intermediate tags
  t1^= s->v3;
  t2^= s->v4;
  //printf("Encrypt Last separate\n");
 
}

// decryption stage.
forceinline void PSASPIN_decrypt_first(state_t* s, uint8_t* m, const uint8_t* c,
                               uint64_t clen) {
    const int nr = 8;
  /* full ciphertext blocks */
  m=m;
  clen=clen;
    word_t nscx = RET(c, 8);
    unsigned char nsrecovered[]="0";

    s->v0 = XOR(s->v0, nscx);
    STORE(nsrecovered, s->v0, 8);
    s->v0 = nscx;
    nscx = RET(c + 8, 8);
    s->v1 = XOR(s->v1, nscx);
    STORE(nsrecovered + 8, s->v1, 8);
    s->v1 = nscx;
    
    P(s, nr);
    t1^= s->v3;
    t2^= s->v4;
 //printf("Decfirst separate\n");
}
forceinline void PSASPIN_decrypt(state_t* s, uint8_t* m, const uint8_t* c,
                               uint64_t clen) {
    const int nr = 8;
  /* full ciphertext blocks */
    word_t cx = RET(c, 8);
    s->v0 = XOR(s->v0, cx);
    STORE(m, s->v0, 8);
    s->v0 = cx;
    cx = RET(c + 8, 8);
    s->v1 = XOR(s->v1, cx);
    STORE(m + 8, s->v1, 8);
    s->v1 = cx;
   
    P(s, nr);
    t1^= s->v3;
    t2^= s->v4;
    lmlen=clen;
    //printf("Dec separate\n");
      
    }
forceinline void PSASPIN_decrypt_last(state_t* s, uint8_t* m, const uint8_t* c,
  
                          uint64_t clen) {
  c=cc; 
  clen=lmlen;
  m=mm;
  /* final ciphertext block */
  word_t* px = &s->v0;
  if (PSASPIN_AEAD_RATE == 16 && clen >= 8) {
    word_t cx = RET(c, 8);
    s->v0 = XOR(s->v0, cx);
    STORE(m, s->v0, 8);
    s->v0 = cx;
    px = &s->v1;
    m += 8;
    c += 8;
    clen -= 8;
    
    
  }
  *px = XOR(*px, LPAD(clen));
  if (clen) {
    word_t cx = RET(c, clen);
    *px = XOR(*px, cx);
    STORE(m, *px, clen);
    *px = CLEAR(*px, clen);
    *px = XOR(*px, cx);
  }
  t1^= s->v3;
  t2^= s->v4;
  //printf("Declast separate\n");
}

// finalization
forceinline void PSASPIN_final(state_t* s, const uint8_t* k) {
  /* RET key session keys */
  //printf("The program passed here in finalization1\n");
  word_t K0, K1, K2;
  PSASPIN_RETkey(&K0, &K1, &K2, k);
  /* finalization stage */
  /*if (CRYPTO_KEYBYTES == 16 && PSASPIN_AEAD_RATE == 8) {
    s->v1 = XOR(s->v1, K1);
    s->v2 = XOR(s->v2, K2);
    printf(" keybytes 16\n");
  }*/
  //if (CRYPTO_KEYBYTES == 16 && PSASPIN_AEAD_RATE == 16) {
    s->v2 = XOR(s->v2, K1);
    s->v3 = XOR(s->v3, K2);
    //printf(" keybytes 16B\n");
  //}/*
  /*if (CRYPTO_KEYBYTES == 20) {
    s->v1 = XOR(s->v1, KEYROT(K0, K1));
    s->v2 = XOR(s->v2, KEYROT(K1, K2));
    s->v3 = XOR(s->v3, KEYROT(K2, WORD_T(0)));
    printf(" keybytes 20\n");
  }*/
  P(s, 8);
  s->v3 = XOR(s->v3, K1);
  s->v4 = XOR(s->v4, K2);
  t1^= s->v3;
  t2^= s->v4;
  //printf("Dec final done\n");
  
}

// ecnryption & decryption templaces
int crypto_aead_encrypt(unsigned char *c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  
  uint64_t ctr=0;// paralle thread counter
  int keyindex=0;
  state_t s;
  //nseclen=nseclen;
  *clen = mlen + CRYPTO_ABYTES; // i removed +nseclen+ from here
  while (adlen >= PSASPIN_AEAD_RATE) {
    //printf("the loop seen");
  PSASPIN_aeadinit(&s, npub, &k[keyindex]);
  PSASPIN_adata(&s, ad, adlen, ctr++);
  ad += PSASPIN_AEAD_RATE;
  adlen -= PSASPIN_AEAD_RATE;
  aad=(uint8_t*)ad;
  aadlen=adlen;
  keyindex++;
  //ctr++;
  }
  PSASPIN_adata_last(&s, ad, adlen, ctr);
  
  ctr=0;
  int enctr=0;
  
  while (mlen >= PSASPIN_AEAD_RATE) {
    if (enctr==0){
      PSASPIN_encrypt_first(&s, c, m, mlen, nsec,adlen);
    c += PSASPIN_AEAD_RATE;
  //nsslen=nseclen;
  cc=c;
  }
  //printf("Go to encrypt");
  PSASPIN_encrypt(&s, c, m, mlen);
  m += PSASPIN_AEAD_RATE;
  c += PSASPIN_AEAD_RATE;
  mlen -= PSASPIN_AEAD_RATE;
  lmlen=mlen;
  cc=c;
  mm=(uint8_t*)m;
  enctr++;
  }
  PSASPIN_encrypt_last(&s, c, m, mlen);// added
  
  PSASPIN_final(&s, k);
 
  /* compute the final tag */
  STOREBYTES(c + mlen, t1, 8);
  STOREBYTES(c + mlen + 8, t2, 8);
  return 0;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,const unsigned char* c, 
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char *k) {
  
  int keyindex=0;
  uint64_t ctr=0;
 ;
  state_t s;
  //(void)nsec;
   if (clen < CRYPTO_ABYTES) return -1;// I changed this code
  *mlen = clen = clen - CRYPTO_ABYTES;
 
 while (adlen >= PSASPIN_AEAD_RATE) {
  PSASPIN_aeadinit(&s, npub, &k[keyindex]);
  PSASPIN_adata(&s, ad, adlen, ctr++);
  ad += PSASPIN_AEAD_RATE;
  adlen -= PSASPIN_AEAD_RATE;
  aad=(uint8_t*)ad;
  aadlen=adlen;
  keyindex++;
  ctr++;
  }
  PSASPIN_adata_last(&s, ad, adlen,ctr);
  ;
 int dectr=0;
 
  while (clen >= PSASPIN_AEAD_RATE) {
if (dectr==0) {
PSASPIN_decrypt_first(&s, m, c, clen);
    c += PSASPIN_AEAD_RATE;
    cc=(uint8_t*)c;
    //printf("the loop seen in dec");
  }

  PSASPIN_decrypt(&s, m, c, clen);
  
   m += PSASPIN_AEAD_RATE;
    c += PSASPIN_AEAD_RATE;
    clen -= PSASPIN_AEAD_RATE;
    lmlen=clen;
    cc=(uint8_t*)c;
   //ctr++;
   dectr++;
   }
  
  PSASPIN_decrypt_last(&s, m, c, clen);
  
  PSASPIN_final(&s, k);
  // compute and veryfy the rag
  t1 = XOR(t1, RETBYTES(c + clen, 8));
  t2 = XOR(t2, RETBYTES(c + clen + 8, 8));
  //printf("Decryption DEC, fin & tag done\n");
  //printf("Decryption began5\n");
  return NOTZERO(t1, t2);
}

/*
int main (){


// from here the test code
// for the rekeying part
uint64_t masterKey = 0xAB01C203D405E6F7;
uint64_t Rtoken =0x0123456789ABCDEF;

int testOutput = 0;
unsigned long long alen = 0;
unsigned long long mlen = 0;
unsigned long long clen = CRYPTO_ABYTES;
unsigned char a[] = "08abcdef01234567";
unsigned char m[] = "I hope that you are Fine." ;
unsigned char c[sizeof(m) + CRYPTO_ABYTES];
unsigned char npub[CRYPTO_NPUBBYTES] = "fedcba0123456789";
unsigned char nsec[CRYPTO_NSECBYTES]={(unsigned char)((uint64_t)m^(uint64_t)a^(uint64_t)npub)};
//unsigned long long nseclen = sizeof(nsec);
uint64_t* sessionkey = PFRK (masterKey, Rtoken);//"08090A0B0C0D0E0F";
unsigned char k[CRYPTO_KEYBYTES] = {(long long) sessionkey};

  // the test output
  alen = strlen((const char*)a);
  mlen = strlen((const char*)m);
  print_test('k', k, CRYPTO_KEYBYTES);
  printf(" ");
  print_test('n', npub, CRYPTO_NPUBBYTES);
  printf("\n");
  print_test('a', a, alen);
  printf(" ");
  print_test('m', m, mlen);
  printf(" -> ");
  testOutput = crypto_aead_encrypt(c, &clen, m, mlen, a, alen, nsec, npub, k);
  print_test('c', c, clen - CRYPTO_ABYTES);
  printf(" ");
  print_test('t', c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
  printf(" -> ");
  testOutput = crypto_aead_decrypt(m, &mlen, c, clen, a, alen, npub, k);
  print_test('a', a, alen);
  printf(" ");
  print_test('m', m, mlen);
  printf("\n");
  return testOutput;

return 0;
}*/

