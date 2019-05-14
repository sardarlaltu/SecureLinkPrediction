#include <myBgn.h>

#define NO_OF_QUERIES 1

typedef struct SLP1_key_t{
    BGN_PK_t * bgnPk;
    BGN_SK_t * bgnSk;
    int keyPerm;
    //permutation key
}SLP1_KEY_t;

typedef struct trapdoor_t{
    int pos_i; //Should  be changed
    int rand_s;
}TRAPDOOR_t;

typedef struct lp_q_res_t{
    element_t * ciphertexts;
    element_t * nhds;
}LP_Q_RES_t;

typedef struct lp2_q_res_t{
    element_t * ciphertexts;
    element_t * m;
}LP2_Q_RES_t;


typedef struct slp1_res_t{
    int maxIndex;
    mpz_t maxScore;
}SLP1_RES_t;

typedef struct slp2_res_t{
    mpz_t * scores;
    int   * indices;
    int     maxIndex;
    mpz_t   maxScore;
}SLP2_RES_t;

extern int ** read_matrix_from_file(char * , int );
extern int ** Allocate_2D_int(int , int );
extern element_t ** Allocate_2D_element(int , int );
extern SLP1_KEY_t * SLP1_Key_Gen( int );
extern element_t **  SLP1_Encrypt_Matrix( int ** , BGN_PK_t * , int );
extern void SLP1_Trapdoor_Gen(TRAPDOOR_t *, int , int );
extern void SLP1_LinkPred_Query(LP_Q_RES_t *, TRAPDOOR_t *,  element_t ** ,BGN_PK_t * , int );
extern void SLP1_Find_Max_Vertex(SLP1_RES_t * , SLP1_KEY_t *,  LP_Q_RES_t *, int );
extern void SLP1_print_slp1_res(SLP1_RES_t *);

extern double time_difference(struct timeval * , struct timeval * );
extern void SLP1_print_times(int ,int,  double, double, int, double, double, double );
extern void SLP1_Clear_LPQRes(LP_Q_RES_t *, int );
extern void SLP1_Clear_All(int **AdjMatrix, element_t **,BGN_PK_t *, int );

extern int **  SLP2_contruct_b_matrix(int **, int );
extern element_t **  SLP2_Encrypt_Matrix( int ** , BGN_PK_t * , int );
extern void SLP2_LinkPred_Query( LP2_Q_RES_t *,TRAPDOOR_t *,  element_t ** , element_t ** , BGN_PK_t * , int);
extern void SLP2_Find_Max_Vertex(SLP2_RES_t * , SLP1_KEY_t *, LP2_Q_RES_t *, int );
extern void SLP2_sort(mpz_t * , int * , int );
extern void SLP2_final_score(SLP1_KEY_t *, element_t *, SLP2_RES_t *,int);
extern void SLP2_print_slp2_res(SLP2_RES_t *);
extern void SLP2_Clear_All(int **, element_t **,int **, element_t **, BGN_PK_t *, int );
