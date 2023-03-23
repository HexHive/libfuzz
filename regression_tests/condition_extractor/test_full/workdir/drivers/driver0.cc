#include <library.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	my_struct *my_struct_p_h0[1] = { 0 };
	int int_s0[1];
	char char_p_s4[128];
	my_struct *my_struct_p_h1[1] = { 0 };
	int int_s1[1];
	char *char_p_h3[128] = { 0 };
	size_t size_t_s0[1];
	int int_s2[1];
	char char_p_s1[128];
	char *char_p_h2[128] = { 0 };
	size_t size_t_s1[1];
	char *char_p_s0 = "gxkpoprtbtdkbgkndysk.bin";
	memcpy(char_p_s4, data, sizeof(char_p_s4));data += sizeof(char_p_s4);
	memcpy(size_t_s0, data, sizeof(size_t_s0));data += sizeof(size_t_s0);
	memcpy(int_s2, data, sizeof(int_s2));data += sizeof(int_s2);
	memcpy(char_p_s1, data, sizeof(char_p_s1));data += sizeof(char_p_s1);
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

	//dyn array init
	memcpy(int_s1, data, sizeof(int_s1));data += sizeof(int_s1);
	char_p_h3[0] = (char*)malloc(int_s1[0]);
	memcpy(char_p_h3[0], data, int_s1[0]);
	data += int_s1[0];

	my_struct_p_h0[0] =  create(char_p_s0);
	if (my_struct_p_h0[0] == 0) goto clean_up;
	get_data(my_struct_p_h0[0], char_p_s1);
	my_struct_p_h1[0] =  create(char_p_s0);
	if (my_struct_p_h1[0] == 0) goto clean_up;
	set_data(my_struct_p_h0[0], char_p_h2[0], int_s0[0]);
	operation(my_struct_p_h1[0]);
	operation(my_struct_p_h0[0]);
	set_data(my_struct_p_h0[0], char_p_h3[0], int_s1[0]);
	int_s2[0] =  get_a(my_struct_p_h0[0]);
	close(my_struct_p_h1[0]);
	my_struct_p_h1[0] = 0;
	get_data(my_struct_p_h0[0], char_p_s4);

clean_up:
	if (my_struct_p_h0[0] != 0) free(my_struct_p_h0[0]);
	if (my_struct_p_h1[0] != 0) free(my_struct_p_h1[0]);
	if (char_p_h3[0] != 0) free(char_p_h3[0]);
	if (char_p_h2[0] != 0) free(char_p_h2[0]);

	return 0;
}