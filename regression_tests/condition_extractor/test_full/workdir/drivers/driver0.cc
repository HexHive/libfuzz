#include <library.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define FIXED_SIZE 9
#define COUNTER_NUMBER 2
#define MIN_SEED_SIZE 25
const unsigned counter_size[COUNTER_NUMBER] = { 8,8 };

#define NEW_DATA_LEN 4096

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	if (Size < MIN_SEED_SIZE) return 0;
	char *char_p_s0 = "aatzkxurbncuvcbsrrem.bin";
	int int_s1[1];
	char char_p_s2[1];
	int int_s0[1];
	void *void_p_h0 = 0;
	my_struct *my_struct_p_h1[1] = { 0 };
	void *void_p_h1[1] = { 0 };
	char *char_p_s1 = "byggliyxpkiuwmozhysb.bin";
	size_t size_t_s1[1];
	size_t size_t_s0[1];
	my_struct *my_struct_p_h0[1] = { 0 };
	memcpy(int_s1, data, sizeof(int_s1));data += sizeof(int_s1);
	memcpy(char_p_s2, data, sizeof(char_p_s2));data += sizeof(char_p_s2);
	memcpy(int_s0, data, sizeof(int_s0));data += sizeof(int_s0);
	//file init
	memcpy(size_t_s0, data, sizeof(size_t_s0));data += sizeof(size_t_s0);
	FILE *p0 = fopen(char_p_s0, "w");
	fwrite(data, size_t_s0[0], 1, p0);
	fclose(p0);data += size_t_s0[0];

	//file init
	memcpy(size_t_s1, data, sizeof(size_t_s1));data += sizeof(size_t_s1);
	FILE *p1 = fopen(char_p_s1, "w");
	fwrite(data, size_t_s1[0], 1, p1);
	fclose(p1);data += size_t_s1[0];

	// void_p_h0 =  my_malloc(int_s0[0]);
	// if (void_p_h0 == 0) goto clean_up;
	// my_free(void_p_h0);
	// void_p_h0 = 0;
	// void_p_h1[0] =  my_malloc(int_s0[0]);
	// if (void_p_h1[0] == 0) goto clean_up;
	// my_free(void_p_h1[0]);
	// void_p_h1[0] = 0;
	my_struct_p_h0[0] =  create(char_p_s0);
	if (my_struct_p_h0[0] == 0) goto clean_up;
	close(my_struct_p_h0[0]);
	my_struct_p_h0[0] = 0;
	my_struct_p_h1[0] =  create(char_p_s1);
	if (my_struct_p_h1[0] == 0) goto clean_up;
	set_b(my_struct_p_h1[0], int_s1[0]);
	int_s1[0] =  get_b(my_struct_p_h1[0]);
	set_data(my_struct_p_h1[0], char_p_s2, int_s0[0]);

clean_up:
	if (void_p_h0 != 0) free(void_p_h0);
	if (my_struct_p_h1[0] != 0) free(my_struct_p_h1[0]);
	if (void_p_h1[0] != 0) free(void_p_h1[0]);
	if (my_struct_p_h0[0] != 0) free(my_struct_p_h0[0]);

	return 0;
}

int cmpfunc (const void * a, const void * b)
{return ( *(unsigned*)a - *(unsigned*)b );}

// Forward-declare the libFuzzer's mutator callback.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {

	if (Size < FIXED_SIZE)return Size;
	unsigned cut[COUNTER_NUMBER] = { 0 };
	uint8_t NewData[NEW_DATA_LEN];
	size_t NewDataSize = sizeof(NewData);
	uint8_t *NewDataPtr = NewData;
	uint8_t *DataPtr = Data;
	size_t NewDataLen = LLVMFuzzerMutate(Data, Size, NEW_DATA_LEN);
	if (NewDataLen < FIXED_SIZE) return NewDataLen;
	size_t DynamicPart = NewDataLen - FIXED_SIZE;
	cut[0] = 0;
	if (DynamicPart == 0) {
		for (int i = 1; i < COUNTER_NUMBER; i++) cut[i] = 0;
	} else {
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
