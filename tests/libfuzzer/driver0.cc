#include <stdint.h>
#include <cstddef>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <cstdlib>
#include <time.h>

/* MIN_SEED_SIZE = 128 (FIXED SIZE) +
                     8 (COUNTER 1) +
                     4 (COUNTER 2)
                ----------------
                   140
*/
#define FIXED_SIZE 128
#define MIN_SEED_SIZE 140
#define COUNTER_NUMBER 2
const unsigned counter_size[COUNTER_NUMBER] = { 8, 4 };

#define NEW_DATA_LEN 4096

int cmpfunc (const void * a, const void * b) {
   return ( *(unsigned*)a - *(unsigned*)b );
}

// Forward-declare the libFuzzer's mutator callback.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {

    // printf("LLVMFuzzerCustomMutator\n");

    if (Size < FIXED_SIZE)
        return Size;

    // printf("check 1 done\n");

    unsigned cut[COUNTER_NUMBER] = { 0 };

    uint8_t NewData[NEW_DATA_LEN];
    size_t NewDataSize = sizeof(NewData);

    uint8_t *NewDataPtr = NewData;
    uint8_t *DataPtr = Data;

    size_t NewDataLen = LLVMFuzzerMutate(Data, Size, NEW_DATA_LEN);

    if (NewDataLen < FIXED_SIZE)
        return NewDataLen;

    // printf("check 2 done\n");

    size_t DynamicPart = NewDataLen - FIXED_SIZE;

    // printf("DynamicPart = %u\n", DynamicPart);
    // find cuts
    cut[0] = 0;
    if (DynamicPart == 0) {
        for (int i = 1; i < COUNTER_NUMBER; i++)
            cut[i] = 0;
    }
    else {
        for (int i = 1; i < COUNTER_NUMBER; i++)
            cut[i] = rand() % DynamicPart;
        qsort(cut, COUNTER_NUMBER, sizeof(unsigned), cmpfunc);
    }

    // copy Fixed Part
    size_t slice_len = FIXED_SIZE;
    memcpy(NewDataPtr, DataPtr, slice_len);
    DataPtr += slice_len;
    NewDataPtr += slice_len;

    size_t NewDataFinalLen = slice_len;
    
    for (int i = 0; i < COUNTER_NUMBER; i++) {
        if (i == COUNTER_NUMBER - 1)
            slice_len = DynamicPart - cut[i];
        else 
            slice_len = cut[i+1] - cut[i];
        memcpy(NewDataPtr, &slice_len, counter_size[i]);
        NewDataPtr += counter_size[i];
        memcpy(NewDataPtr, DataPtr, slice_len);
        DataPtr += slice_len;
        NewDataPtr += slice_len;

        NewDataFinalLen += slice_len + counter_size[i];
    }


    memcpy(Data, NewData, NewDataFinalLen);

    return NewDataFinalLen;
}

// I need some randomness
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    srand(time(0));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size < MIN_SEED_SIZE) {
        // printf("eary exit\n");
        return 0;
    }

    // printf("passed min size\n");
  
    char char_p_s4[128];
    size_t size_t_s1[1];
	char *char_p_s0 = "gxkpoprtbtdkbgkndysk.bin";
	int int_s0[1];	
	char *char_p_h2[128] = { 0 };
	
	memcpy(char_p_s4, data, sizeof(char_p_s4));data += sizeof(char_p_s4);

	//file init
	memcpy(size_t_s1, data, sizeof(size_t_s1));data += sizeof(size_t_s1);
	FILE *p0 = fopen(char_p_s0, "w");
	fwrite(data, size_t_s1[0], 1, p0);
	fclose(p0);data += size_t_s1[0];

	//dyn array init
	memcpy(int_s0, data, sizeof(int_s0));data += sizeof(int_s0);
	char_p_h2[0] = (char*)malloc(int_s0[0]);
	memcpy(char_p_h2[0], data, int_s0[0]);
	data += int_s0[0];

    if (size_t_s1[0] != 0) {
        printf("wrote file %zu\n", size_t_s1[0]);
    }

    if (int_s0[0] != 0) {
        printf("wrote array %d\n", int_s0[0]);
    }

    if (size_t_s1[0] != 0 && int_s0[0] != 0)
        abort();


clean_up:
	if (char_p_h2[0] != 0) free(char_p_h2[0]);

    return 0;
}