/****************************************************
Name of the file: <myBgn_test.c>                    *
Author: < Anonymous >                            	*
Must Need: <myBgn.h> and <myBgn.c>                  *
Example: <myBgn_test.c>                             *
The Secure Link Prediction Problem					*
***************************************************/

#include <pbc/pbc.h>
#include<common.h>
#include<myBgn.h>
int main() {
    int lambda = 512;// Security parameter

    BGN_KEYS_t *bgn_keys;
    bgn_keys= BGN_Key_Gen(lambda);
    BGN_print_pk(bgn_keys->PK);

    element_t  * cipher_text;
    mpz_t *plain_text;


    cipher_text = BGN_encrypt_G1(bgn_keys->PK,11);
    element_printf("ciphertext = %B\n",*cipher_text);
    plain_text = BGN_decrypt_G1(bgn_keys->PK, bgn_keys->SK, cipher_text);
    gmp_printf ("plain_text = %Zd\n",  *plain_text);


    cipher_text = BGN_encrypt_GT(bgn_keys->PK,21);
    element_printf("ciphertext = %B\n",*cipher_text);
    plain_text = BGN_decrypt_GT(bgn_keys->PK, bgn_keys->SK, cipher_text);
    gmp_printf ("plain_text = %Zd\n",  *plain_text);


    cipher_text = BGN_encrypt(bgn_keys->PK, 15, 0);
    element_printf("ciphertext = %B\n",*cipher_text);
    plain_text = BGN_decrypt(bgn_keys->PK, bgn_keys->SK, cipher_text, 0);
    gmp_printf ("plain_text = %Zd\n",  *plain_text);


    cipher_text = BGN_encrypt(bgn_keys->PK, 5, 1);
    element_printf("ciphertext = %B\n",*cipher_text);
    plain_text = BGN_decrypt(bgn_keys->PK, bgn_keys->SK, cipher_text, 1);
    gmp_printf ("plain_text = %Zd\n",  *plain_text);

    printf("=========--------BGN Test Success-------=========\n");
    //clear values before exit
    return 0;
}
