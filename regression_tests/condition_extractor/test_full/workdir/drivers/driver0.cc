#include <library.h>

#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	my_struct *my_struct_p_h0[1];
	int int_s2[1];
	my_struct *my_struct_p_h1[1];
	size_t size_t_s0[1];
	int int_s1[1];
	size_t size_t_s1[1];
	char char_pp_s0[128];
	char *char_p_h1[1];
	char *char_p_s2[1] = {"yltmhyvvfjbtdbcjfeep.bin"};
	char *char_p_s0[1] = {"hovtogoiairhigjgzvec.bin"};
	int int_s3[1];
	int int_s0[1];
	memcpy(int_s1, data, sizeof(int_s1));data += sizeof(int_s1);
	memcpy(char_pp_s0, data, sizeof(char_pp_s0));data += sizeof(char_pp_s0);
	memcpy(int_s3, data, sizeof(int_s3));data += sizeof(int_s3);
	memcpy(int_s0, data, sizeof(int_s0));data += sizeof(int_s0);
	//file init
	memcpy(size_t_s0, data, sizeof(size_t_s0));data += sizeof(size_t_s0);
	FILE *p0 = fopen(char_p_s0[0], "w");
	fwrite(data, 1, size_t_s0[0], p0);
	fclose(p0);data += size_t_s0[0];

	//dyn array init
	memcpy(int_s2, data, sizeof(int_s2));data += sizeof(int_s2);
	char_p_h1[0] = (char*)malloc(int_s2[0]);
	memcpy(char_p_h1[0], data, int_s2[0]);
	data += int_s2[0];

	//file init
	memcpy(size_t_s1, data, sizeof(size_t_s1));data += sizeof(size_t_s1);
	FILE *p1 = fopen(char_p_s2[0], "w");
	fwrite(data, 1, size_t_s1[0], p1);
	fclose(p1);data += size_t_s1[0];

	my_struct_p_h0[0] =  create(char_p_s0[0]);
	int_s0[0] =  get_a(my_struct_p_h0[0]);
	int_s1[0] =  get_b(my_struct_p_h0[0]);
	int_s1[0] =  get_a(my_struct_p_h0[0]);
	set_data(my_struct_p_h0[0], char_p_h1[0], int_s2[0]);
	set_a(my_struct_p_h0[0], int_s3[0]);
	get_data(my_struct_p_h0[0], char_pp_s0[0]);
	set_a(my_struct_p_h0[0], int_s1[0]);
	close(my_struct_p_h0[0]);
	my_struct_p_h1[0] =  create(char_p_s2[0]);

	return 0;
}