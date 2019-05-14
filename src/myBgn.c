
/****************************************************
Name of the file: <myBgn.c>                    		*
Author: < Anonymous >                            	*
Must Need: <myBgn.h>                  				*
Example: <myBgn_test.c>                             *
The Secure Link Prediction Problem					*
***************************************************/


#include <pbc/pbc.h>
#include <myBgn.h>
#include<stdio.h>

//##############################################################################
BGN_KEYS_t * BGN_Key_Gen(int lambda){

    BGN_KEYS_t * bgn_keys = (BGN_KEYS_t *)malloc(sizeof(BGN_KEYS_t));
    BGN_PK_t   * bgn_pk   = (BGN_PK_t *)malloc(sizeof(BGN_PK_t));
    BGN_SK_t   * bgn_sk   = (BGN_SK_t *)malloc(sizeof(BGN_SK_t));

    mpz_t p; // q2 of bgn
    mpz_init(p);  /* random prime p Generation */
    pbc_mpz_randomb(p, lambda);
    mpz_nextprime(p, p);

    mpz_init(bgn_sk->q);  /* random prime q Generation */
    pbc_mpz_randomb(bgn_sk->q, lambda);
    mpz_nextprime(bgn_sk->q, bgn_sk->q);

    mpz_init(bgn_pk->n); // Initializing n
    mpz_mul(bgn_pk->n, bgn_sk->q, p); //n = p*q

    pbc_param_t param;
    pbc_param_init_a1_gen(param, bgn_pk->n);    //Initializing Symmetric pairing parameter
    pairing_init_pbc_param(bgn_pk->pairing_e, param); /*pairing Generation*/

    element_init_G1(bgn_pk->g, bgn_pk->pairing_e);
    element_init_G1(bgn_pk->h, bgn_pk->pairing_e);
    element_init_GT(bgn_pk->g1, bgn_pk->pairing_e);
    element_init_GT(bgn_pk->h1, bgn_pk->pairing_e);
    element_init_G1(bgn_sk->g_cap, bgn_pk->pairing_e);
    element_init_GT(bgn_sk->g1_cap, bgn_pk->pairing_e);

    BGN_generators_gen(bgn_pk,bgn_sk);

    mpz_t r;
    mpz_init(r); //
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm (r, state, bgn_pk-> n);

    element_t u;
    element_init_G1(u, bgn_pk->pairing_e);
    element_pow_mpz(u, bgn_pk->g, r);

    element_pow_mpz(bgn_pk->h, u, p);//Finds power x of g and stores in h.
    pairing_apply(bgn_pk->h1, bgn_pk->g, bgn_pk->h, bgn_pk->pairing_e); //h1 = e(g,h)

    element_pow_mpz(bgn_sk->g_cap, bgn_pk->g, bgn_sk->q);//Finds power q of g and stores in g_cap.
    element_pow_mpz(bgn_sk->g1_cap, bgn_pk->g1, bgn_sk->q);//Finds power q of g and stores in g_cap.

    bgn_keys->PK = bgn_pk;
    bgn_keys->SK = bgn_sk;
    return bgn_keys;
}


//##############################################################################
void BGN_generators_gen(BGN_PK_t *bgn_pk, BGN_SK_t *bgn_sk){

    element_t identity_G1, identity_GT, g1_guess, gt_guess, temp_G1, temp_GT;
    mpz_t p;

    element_init_G1(g1_guess, bgn_pk->pairing_e);
    element_init_GT(gt_guess, bgn_pk->pairing_e);
    element_init_G1(identity_G1, bgn_pk->pairing_e);
    element_init_GT(identity_GT, bgn_pk->pairing_e);
    element_init_G1(temp_G1, bgn_pk->pairing_e);
    element_init_GT(temp_GT, bgn_pk->pairing_e);

    mpz_init(p); //s=0
    element_random(identity_G1);
    element_random(identity_GT);

    element_pow_mpz(identity_G1, identity_G1, p);//
    element_pow_mpz(identity_GT, identity_GT, p);//.

    mpz_div(p, bgn_pk->n, bgn_sk->q);

    while(1){
        element_random(g1_guess);
        element_printf("******* Guessed Generator: %B\n",g1_guess );

        if (!element_cmp(identity_G1, g1_guess)) continue; //check whether identity
        element_pow_mpz(temp_G1, g1_guess, bgn_sk->q);
        if (!element_cmp(identity_G1, temp_G1)) continue;//check whether order = q
        element_pow_mpz(temp_G1, g1_guess, p);
        if (!element_cmp(identity_G1, temp_G1)) continue; //check whether order = p

        pairing_apply(gt_guess, g1_guess, g1_guess, bgn_pk->pairing_e);

        if (!element_cmp(identity_GT, gt_guess)) continue; //check whether identity
        element_pow_mpz(temp_GT, gt_guess, bgn_sk->q);
        if (!element_cmp(identity_GT, temp_GT)) continue;//check whether order = q
        element_pow_mpz(temp_GT, gt_guess, p);
        if (!element_cmp(identity_GT, temp_GT)) continue; //check whether order = p

        break;
    }
    element_set(bgn_pk->g, g1_guess);
    element_set(bgn_pk->g1, gt_guess);

    return;
}

//##############################################################################
element_t * BGN_encrypt(BGN_PK_t *bgn_pk, int a, int flag){

    mpz_t r;
    mpz_init(r); //
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm (r, state, bgn_pk-> n);

    mpz_t _a;
    mpz_init(_a); //
    mpz_set_si(_a,a);

    element_t *c_text = (element_t *) malloc(sizeof(element_t ));
    if (flag == 0){//Encryption in G
        element_init_G1(*c_text,bgn_pk->pairing_e);
        element_pow2_mpz(*c_text, bgn_pk-> g, _a, bgn_pk->h, r); //g^a*h^r
    }else if (flag==1) { //encryption in GT
        element_init_GT(*c_text,bgn_pk->pairing_e);
        element_pow2_mpz(*c_text, bgn_pk-> g1, _a, bgn_pk->h1, r); //(g1)^a.(h1)^ r
    }else{
        printf("Error in Encryption: Wrong Argument:\n" );
        exit(0);
    }

    return c_text;
}


//##############################################################################
//Flag =0 for G1 and  flag = 1 for  GT,
mpz_t * BGN_decrypt(BGN_PK_t *bgn_pk, BGN_SK_t *bgn_sk, element_t * cipher_text, int flag){

    mpz_t * plain_text = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(*plain_text);

    element_t temp, temp2;
    if (flag == 0){//Decryption in G
        element_init_G1(temp,bgn_pk->pairing_e );
        element_init_G1(temp2,bgn_pk->pairing_e );
    }else if (flag==1) { //Decryption in GT
        element_init_GT(temp,bgn_pk->pairing_e );
        element_init_GT(temp2,bgn_pk->pairing_e );
    }else{
        printf("Error in Decryption: Wrong Argument:\n" );
        exit(0);
    }


    element_pow_mpz(temp, *cipher_text, *plain_text); //set temp = g^0 or 1
    element_pow_mpz(temp2, *cipher_text, bgn_sk->q);

    while (element_cmp( temp,temp2) !=0){
        mpz_add_ui (*plain_text, *plain_text, 1);
        if (flag==0) {
            element_mul(temp, temp, bgn_sk->g_cap);
        }else{
            element_mul(temp, temp, bgn_sk->g1_cap);
        }
    }

    return plain_text;

}


//##############################################################################
void BGN_print_pk( BGN_PK_t * bgn_pk){

    gmp_printf ("n = %Zd\n",  bgn_pk->n);
    element_printf("g = %B\n",bgn_pk->g );
    element_printf("h = %B\n",bgn_pk->h );
    element_printf("g1 = %B\n",bgn_pk->g1 );
    element_printf("h1 = %B\n",bgn_pk->h1 );
    return;
}

void BGN_print_sk( BGN_SK_t * bgn_sk){
    gmp_printf ("q = %Zd\n",  bgn_sk->q);
    element_printf("g_cap = %B\n",bgn_sk->g_cap );
    return;
}


//%%%%%%%%%%%%%%%% Codes belllow this no more required %%%%%%%%%%%%%%%%%%%%%%%%%

//##############################################################################
element_t * BGN_encrypt_G1(BGN_PK_t *bgn_pk, int a){
    mpz_t r;
    mpz_init(r); //
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm (r, state, bgn_pk-> n);

    mpz_t _a;
    mpz_init(_a); //
    mpz_set_si(_a,a);

    element_t *c_text = (element_t *) malloc(sizeof(element_t ));
    element_init_G1(*c_text,bgn_pk->pairing_e);
    //g^a*h^r
    element_pow2_mpz(*c_text, bgn_pk-> g, _a, bgn_pk->h, r);

    return c_text;
}


//##############################################################################
mpz_t * BGN_decrypt_G1(BGN_PK_t *bgn_pk, BGN_SK_t *bgn_sk, element_t * cipher_text){
    mpz_t * plain_text = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(*plain_text);

    element_t temp, temp2;
    element_init_G1(temp,bgn_pk->pairing_e );
    element_init_G1(temp2,bgn_pk->pairing_e );

    element_pow_mpz(temp, *cipher_text, *plain_text); //set temp = g^0 or 1
    element_pow_mpz(temp2, *cipher_text, bgn_sk->q);

    while (element_cmp( temp,temp2) !=0){
        mpz_add_ui (*plain_text, *plain_text, 1);
        element_mul(temp, temp, bgn_sk->g_cap);
    }

    return plain_text;
}

//##############################################################################
element_t * BGN_encrypt_GT(BGN_PK_t *bgn_pk, int a){

    mpz_t r;
    mpz_init(r); //
    gmp_randstate_t state;
    gmp_randinit_default(state);
    mpz_urandomm (r, state, bgn_pk-> n);

    mpz_t _a;
    mpz_init(_a); //
    mpz_set_si(_a,a);

    element_t *c_text = (element_t *) malloc(sizeof(element_t ));
    element_init_GT(*c_text,bgn_pk->pairing_e);
    //g^a*h^r
    element_pow2_mpz(*c_text, bgn_pk-> g1, _a, bgn_pk->h1, r);

    return c_text;
}


//##############################################################################
mpz_t * BGN_decrypt_GT(BGN_PK_t *bgn_pk, BGN_SK_t *bgn_sk, element_t * cipher_text){

    mpz_t * plain_text = (mpz_t *)malloc(sizeof(mpz_t));
    mpz_init(*plain_text);

    element_t temp, temp2;
    element_init_GT(temp,bgn_pk->pairing_e );
    element_init_GT(temp2,bgn_pk->pairing_e );

    element_pow_mpz(temp, *cipher_text, *plain_text); //set temp = g^0 or 1
    element_pow_mpz(temp2, *cipher_text, bgn_sk->q);

    while (element_cmp( temp,temp2) !=0){
        mpz_add_ui (*plain_text, *plain_text, 1);
        element_mul(temp, temp, bgn_sk->g1_cap);
    }

    return plain_text;

}
