/****************************************************
Name of the file: <myBgn.h>                         *
Author: < Laltu Sardar >                            *
Must Need: <myBgn.c>                                *
Example: <myBgn_test.c>                             *
***************************************************/

/*
In our scheme
(q 1 , q 2 , G, G 1 , e) = (q, p, G1, GT)
PK=(n, G, G 1 , e, g, h)= (n, G1, GT , pairing_e, g, h)
SK= (q1)=(q)

*/
typedef struct BGN_pk{
    mpz_t n;                // n product of the primes p and q
    pairing_t pairing_e;    // pairing e, No need to keep G1 and GT
    element_t g;            //from G1
    element_t h;            //from G1
    element_t g1;
    element_t h1;
}BGN_PK_t;

typedef struct BGN_sk{
    mpz_t q;
    element_t g_cap; //For decryption in G1
    element_t g1_cap; //For decryption in G1
}BGN_SK_t;

typedef struct BGN_keys{
    struct BGN_pk * PK;
    struct BGN_sk * SK;
}BGN_KEYS_t;


extern BGN_KEYS_t * BGN_Key_Gen(int);
extern void BGN_generators_gen(BGN_PK_t *  ,BGN_SK_t *);

extern element_t * BGN_encrypt(BGN_PK_t *, int , int );
extern mpz_t * BGN_decrypt(BGN_PK_t * , BGN_SK_t * , element_t * , int);

extern element_t * BGN_encrypt_G1(BGN_PK_t * , int );
extern mpz_t * BGN_decrypt_G1(BGN_PK_t * , BGN_SK_t * , element_t *  );

extern element_t * BGN_encrypt_GT(BGN_PK_t * , int );
extern mpz_t * BGN_decrypt_GT(BGN_PK_t * , BGN_SK_t * , element_t *  );

extern void BGN_print_pk( BGN_PK_t * );
extern void BGN_print_sk( BGN_SK_t * );
