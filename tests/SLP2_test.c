#include <pbc/pbc.h>
#include <time.h>
#include <sys/time.h>

#include<string.h>
//#include <myBgn.h>
#include <SLP2.h>

int  main(int argc, char const *argv[]) {
    /*Inputs--
    1. Input File Path------> argv[1]
    2. no Of Nodes ---------> argv[2] , noOfNodes
    3. Security parameter --> argv[3] , lambda
    */
    // +++++++ Variable Declaration++++++
    int noOfNodes, lambda =10;
    int ** AdjMatrix, **BMatrix;
    char fileName[100];
    element_t ** EncMatrixA, **EncMatrixB;
    SLP1_KEY_t  * slp1_KEY;
    TRAPDOOR_t  trapdoor;
    LP2_Q_RES_t  lp2Qres;
    SLP2_RES_t   slp2Res;

    //++++ Helping Variables+++++++
    struct timeval  startTime, endTime;
    double runTimeKG, runTimeEM, runTimeTG, runTimeLPQ, runTimeFMV;
    int noOfLPQueries, vertId;
    // ++++++++ argument Checking ++++
    if( argc != 4  ) {
      printf("Please Give Arguments graphSourcefile and noOfNodes\n");
      exit(0);
   }
    //+++++Input checking +++
    //argv[2] ---> fileName
    strcpy(fileName, argv[1]);
    noOfNodes =atoi(argv[2]);
    lambda    =atoi(argv[3]);
    if ( noOfNodes<1||lambda<10 ){
        printf("Error in Arguments\n" );
        exit(0);
    }
    srand(time(NULL));


    //=========== Main Part starts ===========
    //----- Adjacency Matrix Generation
    AdjMatrix = read_matrix_from_file(fileName, noOfNodes);//Loading Adjacency Matrix
    BMatrix = SLP2_contruct_b_matrix(AdjMatrix,noOfNodes);
    //--------- SLP1 Key Generation----------
    gettimeofday(&startTime, NULL);
    slp1_KEY  = SLP1_Key_Gen(lambda);
    gettimeofday(&endTime, NULL);
    runTimeKG=time_difference(&startTime,&endTime);

    //--------- SLP1 Encrypted Matrix Generation----------
    gettimeofday(&startTime, NULL);
    EncMatrixA = SLP1_Encrypt_Matrix(AdjMatrix,slp1_KEY->bgnPk,noOfNodes);
    EncMatrixB = SLP2_Encrypt_Matrix(BMatrix,slp1_KEY->bgnPk,noOfNodes);
    gettimeofday(&endTime, NULL);
    runTimeEM=time_difference(&startTime,&endTime);



    runTimeLPQ=0.0; runTimeFMV=0.0, runTimeTG=0.0;
    noOfLPQueries=0, vertId=0;
    while(noOfLPQueries < NO_OF_QUERIES){
        //printf("Give vertex id: (< %d): ",noOfNodes);
        //scanf("%d",&vertId);
        vertId = rand() % noOfNodes;
        //vertId = (13 * (noOfLPQueries+2)) % noOfNodes;
        gettimeofday(&startTime, NULL);
        SLP1_Trapdoor_Gen(&trapdoor, vertId, slp1_KEY->keyPerm);
        gettimeofday(&endTime, NULL);
        runTimeTG += time_difference(&startTime,&endTime);


        printf("Queried vertex id: %d\n",vertId);
        //--------- SLP1 Link Pred Query by Cloud Server----------
        gettimeofday(&startTime, NULL);
        SLP2_LinkPred_Query(&lp2Qres,&trapdoor, EncMatrixA, EncMatrixB, slp1_KEY->bgnPk, noOfNodes);
        gettimeofday(&endTime, NULL);
        runTimeLPQ += time_difference(&startTime,&endTime);
        //--------- SLP1 Finding Max vertex by Proxy Server----------
        gettimeofday(&startTime, NULL);
        SLP2_Find_Max_Vertex(&slp2Res,slp1_KEY,&lp2Qres, noOfNodes );
        gettimeofday(&endTime, NULL);
        runTimeFMV += time_difference(&startTime,&endTime);
        SLP2_final_score(slp1_KEY,(lp2Qres.m), &slp2Res, noOfNodes);
        SLP2_print_slp2_res(&slp2Res);
        noOfLPQueries++;
    }
    SLP1_print_times(noOfNodes, lambda, runTimeKG, runTimeEM, noOfLPQueries, runTimeTG, runTimeLPQ, runTimeFMV);

    SLP2_Clear_All(AdjMatrix, EncMatrixA, BMatrix,EncMatrixB, slp1_KEY->bgnPk,noOfNodes);
    printf("Success\n" );
    return 0;
}
