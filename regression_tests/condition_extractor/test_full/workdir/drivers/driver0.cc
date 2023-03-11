#include <library.h>

#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	char char_p_3[1][1];
	char char_p_2[1][1];
	size_t size_t_1[1];
	size_t size_t_0[1];
	size_t size_t_3[1];
	int int_2[1];
	size_t size_t_2[1];
	char *char_p_4[1] = {"scxoqezslhzggjdhjfmg.bin"};
	size_t size_t_4[1];
	int int_0[1];
	my_struct *my_struct_p_1[1];
	int int_1[1];
	char *char_p_0[1] = {"ttzrfioravdbnwuvubfc.bin"};
	char char_p_1[1][1];
	my_struct *my_struct_p_0[1];
	my_struct *my_struct_p_2[1];
	memcpy(size_t_1, data, sizeof(size_t_1));data += sizeof(size_t_1);
	memcpy(size_t_0, data, sizeof(size_t_0));data += sizeof(size_t_0);
	memcpy(size_t_2, data, sizeof(size_t_2));data += sizeof(size_t_2);
	//file init
	memcpy(size_t_3, data, sizeof(size_t_3));data += sizeof(size_t_3);
	FILE *p0 = fopen(char_p_0[0], "w");
	fwrite(data, 1, size_t_3[0], p0);
	fclose(p0);data += size_t_3[0];

	//dyn array init
	memcpy(int_0, data, sizeof(int_0));data += sizeof(int_0);
	char_p_1[0] = (char*)malloc(int_0[0]);
	memcpy(char_p_1[0], data, int_0[0]);
	data += int_0[0];

	//dyn array init
	memcpy(int_1, data, sizeof(int_1));data += sizeof(int_1);
	char_p_2[0] = (char*)malloc(int_1[0]);
	memcpy(char_p_2[0], data, int_1[0]);
	data += int_1[0];

	//dyn array init
	memcpy(int_2, data, sizeof(int_2));data += sizeof(int_2);
	char_p_3[0] = (char*)malloc(int_2[0]);
	memcpy(char_p_3[0], data, int_2[0]);
	data += int_2[0];

	//file init
	memcpy(size_t_4, data, sizeof(size_t_4));data += sizeof(size_t_4);
	FILE *p1 = fopen(char_p_4[0], "w");
	fwrite(data, 1, size_t_4[0], p1);
	fclose(p1);data += size_t_4[0];

	my_struct_p_0[0] =  create(char_p_0[0]);
	set_data(my_struct_p_0[0], char_p_1[0], int_0[0]);
	close(my_struct_p_0[0]);
	my_struct_p_1[0] =  create(char_p_0[0]);
	my_struct_p_1[0] =  create(char_p_0[0]);
	set_data(my_struct_p_1[0], char_p_2[0], int_1[0]);
	close(my_struct_p_1[0]);
	my_struct_p_2[0] =  create(char_p_0[0]);
	set_data(my_struct_p_2[0], char_p_3[0], int_2[0]);
	my_struct_p_2[0] =  create(char_p_4[0]);

	return 0;
}