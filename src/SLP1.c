
/****************************************************
Name of the file: <SLP1.c>                    		*
Author: < Anonymous >                            	*
Must Need: <SLP1.h>                  				*
Example: <SLP1_test.c>                             	*
The Secure Link Prediction Problem					*
***************************************************/


#include <pbc/pbc.h>
#include <SLP1.h>

//++++++++++++++++++++++++++++++++++++++++++++
SLP1_KEY_t * SLP1_Key_Gen(int lambda ){
    SLP1_KEY_t *slp1_KEY;
    BGN_KEYS_t *bgn_keys;

    slp1_KEY = (SLP1_KEY_t *)malloc(sizeof(SLP1_KEY_t));
    bgn_keys= BGN_Key_Gen(lambda);

    slp1_KEY->bgnPk = bgn_keys->PK;
    slp1_KEY->bgnSk = bgn_keys->SK;
    slp1_KEY->keyPerm = 123;//edit permutation Later???

    return slp1_KEY;
}

//++++++++++++++++++++++++++++++++++++++++++++
element_t **  SLP1_Encrypt_Matrix(int ** AdjMatrix, BGN_PK_t * bgn_pk, int noOfNodes){
    int i,j;
    element_t * cipher_text;
    element_t ** EncMatrix;

    EncMatrix = Allocate_2D_element(noOfNodes, noOfNodes);
    for (i= 0 ; i< noOfNodes;i++){
        for (j= 0 ; j< noOfNodes;j++){
            element_init_G1(EncMatrix[i][j], bgn_pk->pairing_e);
            cipher_text = BGN_encrypt(bgn_pk, AdjMatrix[i][j], 0);
            element_set(EncMatrix[i][j],*cipher_text);
        }
    }
    // ids are not encrypted till now ???
    return EncMatrix;
}

//++++++++++++++++++++++++++++++++++++++++++++
void SLP1_Trapdoor_Gen(TRAPDOOR_t *trapdoor, int vertId, int keyPerm){
    int pos_i;
    int rand_s;

    pos_i = vertId; //Since Till vertex id is not encrypted ???
    rand_s = 1;//Should be edited ???

    trapdoor -> pos_i = pos_i;
    trapdoor -> rand_s = rand_s;

    return;
}

//++++++++++++++++++++++++++++++++++++++++++++
void SLP1_LinkPred_Query( LP_Q_RES_t *lpQres,TRAPDOOR_t *trapdoor,  element_t ** EncMatrix,BGN_PK_t * bgn_pk, int noOfNodes){
    int i, k;
    int pos;

    pos = trapdoor -> pos_i;
    element_t * ciphertexts, *nhds, temp;

    ciphertexts = (element_t *)malloc(noOfNodes*sizeof(element_t));
    nhds = (element_t *)malloc(noOfNodes*sizeof(element_t));

    mpz_t r;
    mpz_init(r); //
    gmp_randstate_t state;
    gmp_randinit_default(state);

    element_init_GT(temp,bgn_pk->pairing_e);
    for (i= 0; i<noOfNodes;i++){
        //printf("Ongoing Score with vertgex id %d\n",i );
        mpz_urandomm (r, state, bgn_pk-> n);
        element_init_GT(ciphertexts[i],bgn_pk->pairing_e);
        
        element_pow_mpz(ciphertexts[i], bgn_pk->h1, r);
        if (i!=pos){
            for (k= 0; k<noOfNodes;k++){
                pairing_apply(temp, EncMatrix[pos][k], EncMatrix[i][k], bgn_pk->pairing_e);
                element_mul(ciphertexts[i],ciphertexts[i], temp);
            }
        }

    }

    for (i= 0; i<noOfNodes;i++){
        mpz_urandomm (r, state, bgn_pk->n);
        element_init_G1(nhds[i],bgn_pk->pairing_e);
        element_pow_mpz(nhds[i], bgn_pk->h, r);
        element_mul(nhds[i],nhds[i],EncMatrix[pos][i]);
    }

    lpQres -> ciphertexts = ciphertexts;
    lpQres -> nhds = nhds;
    return ;
}


//++++++++++++++++++++++++++++++++++++++++++++
void SLP1_Find_Max_Vertex(SLP1_RES_t * slp1Res, SLP1_KEY_t *slp1_KEY, LP_Q_RES_t *lpQres, int noOfNodes){
    int i, maxIndex=0;
    element_t * ciphertexts = lpQres -> ciphertexts;
    element_t * nhds = lpQres -> nhds;
    mpz_t * a, * s;
    mpz_t maxScore, mpzZero;

    mpz_init(maxScore);
    mpz_init(mpzZero);

    for (i = 0 ; i< noOfNodes ; i++){
        a= BGN_decrypt(slp1_KEY->bgnPk, slp1_KEY->bgnSk, &nhds[i], 0);
        if(mpz_cmp(*a,mpzZero )==0){
            s= BGN_decrypt(slp1_KEY->bgnPk, slp1_KEY->bgnSk, &ciphertexts[i], 1);
            if (mpz_cmp(maxScore,*s)<0){
                mpz_set(maxScore,*s);
                maxIndex = i;
            }
        }
    }
    mpz_set(slp1Res->maxScore, maxScore);
    slp1Res->maxIndex = maxIndex;
    SLP1_Clear_LPQRes(lpQres,noOfNodes);
    return;
}

void SLP1_Clear_LPQRes(LP_Q_RES_t *lpQres, int noOfNodes){
    int i = 0;
    element_t * ciphertexts = lpQres -> ciphertexts;
    element_t * nhds = lpQres -> nhds;

    for (i = 0; i< noOfNodes; i++){
        element_clear(ciphertexts[i]);
        element_clear(nhds[i]);
    }
    return;
}

void SLP1_Clear_All(int **AdjMatrix, element_t **EncMatrix,BGN_PK_t * bgnPk, int noOfNodes) {
    int i = 0,j=0;
    for (i = 0; i< noOfNodes; i++){
        for (j = 0; j< noOfNodes; j++){
            element_clear(EncMatrix[i][j]);
        }
    }
    element_clear(bgnPk->g);
    element_clear(bgnPk->h);
    element_clear(bgnPk->g1);
    element_clear(bgnPk->h1);
    pairing_clear(bgnPk->pairing_e);

    for (j = 0; j< noOfNodes; j++){
        free(EncMatrix[j]);
        free(AdjMatrix[j]);
    }
    free(EncMatrix);
    free(AdjMatrix);
    return ;
}


//++++++++++++++++++++++++++++++++++++++++++++
void SLP1_print_slp1_res(SLP1_RES_t *slp1Res) {
    printf("Resulted Vertex ID : %d\n", slp1Res->maxIndex );
    gmp_printf("Resulted Max Score: %Zd\n", slp1Res->maxScore);
    return;
}


//++++++++++++++++++++++++++++++++++++++++++++
int ** read_matrix_from_file(char * fileName, int noOfNodes){
    int i=0, j=0, counter=0;
    int edge_counter=0;
    FILE* filePtr;
    int **  AdjMatrix;

    AdjMatrix =Allocate_2D_int(noOfNodes,noOfNodes);

    if ((filePtr = fopen(fileName, "r"))==NULL){
        printf("Error in opening -- %s\n",fileName );
        exit(0);
    }

    while (1){
        if (fscanf(filePtr,"%d", &i) == EOF){
            break;
        }
        if (fscanf(filePtr,"%d", &j) == EOF){
            printf("Error in Reading %s \n",fileName );
            return NULL;
        }
        if(i<noOfNodes&&j<noOfNodes){
            AdjMatrix[i][j] =1;
            AdjMatrix[j][i] =1;
            edge_counter++;
        }
        //if(i>=noOfNodes&&j>=noOfNodes){
        //    break;
        //}
        counter ++;
    }
    fclose(filePtr);

    FILE *f = fopen("edgeCount_slp1","a+");
    fprintf(f, "%d\t%d\t%s\n",noOfNodes,edge_counter,fileName );
    fclose(f);

    printf("%d line scanned %d %d \n",counter, i,j );
    return AdjMatrix;
}

//++++++++++++++++++++++++++++++++++++++++++++
int ** Allocate_2D_int(int n, int m){
    int ** arr, i,j;
    if ((arr = (int **) malloc (m* sizeof(int*)) )== NULL){
        printf("Memory Allocatoin Failutre\n" );
        exit(0);
    }
    for (i=0;i<m;i++){
        if ((arr[i] = (int *) malloc (n* sizeof(int)) )== NULL){
            printf("Memory Allocatoin Failutre\n" );
            exit(0);
        }
    }
    for (i = 0 ; i <m ;i++){
        for (j = 0 ; j <n ;j++){
            arr[i][j]=0;
        }
    }
    return arr;
}

//++++++++++++++++++++++++++++++++++++++++++++
element_t ** Allocate_2D_element(int n, int m){
    element_t ** arr;
    int  i;

    if ((arr = (element_t **) malloc (m* sizeof(element_t*)) )== NULL){
        printf("Memory Allocatoin Failutre\n" );
        exit(0);
    }
    for (i=0;i<m;i++){
        if ((arr[i] = (element_t *) malloc (n* sizeof(element_t)) )== NULL){
            printf("Memory Allocatoin Failutre\n" );
            exit(0);
        }
    }

    return arr;
}

//++++++++++++++++++++++++++++++++++++++++++++
double time_difference(struct timeval * startTime, struct timeval * endTime){
    return  (double) (endTime->tv_usec - startTime->tv_usec) / 1000000 + (double) (endTime->tv_sec - startTime->tv_sec);
}

void SLP1_print_times(int noOfNodes, int lambda,  double runTimeKG,
                double runTimeEM, int noOfLPQueries, double runTimeTG,
                double runTimeLPQ, double runTimeFMV ){
    runTimeLPQ /= noOfLPQueries;
    runTimeFMV /= noOfLPQueries;
    runTimeTG /= noOfLPQueries;

    printf("------------------------------------------\n");
    printf("Time taken by the experiment are as follows \n");
    printf("runTimeKG  -> %lf sec\n", runTimeKG);
    printf("runTimeEM  -> %lf sec\n", runTimeEM);
    printf("runTimeLPQ -> %lf sec\n", runTimeLPQ);
    printf("runTimeFMV -> %lf sec\n", runTimeFMV);
    printf("number of LP Queries ->%d\n",noOfLPQueries );
    printf("------------------------------------------\n");

    FILE *filePtr = fopen("SLP1_results","a+");
    fprintf(filePtr, "%d ",noOfNodes);  //Number of vertices
    fprintf(filePtr, "%d ",lambda);     //Security Bits
    fprintf(filePtr, "%lf ",runTimeKG); //Key Generation time
    fprintf(filePtr, "%lf ",runTimeEM); //Time taken to encrypt Matrix
    fprintf(filePtr, "%d ",noOfLPQueries);  //Number of Queries
    fprintf(filePtr, "%lf ",runTimeTG);     //Avarage per query
    fprintf(filePtr, "%lf ",runTimeLPQ);    //Avarage per query
    fprintf(filePtr, "%lf \n",runTimeFMV);  //Avarage per query
    fclose(filePtr);

    return;
}
