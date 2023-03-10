#include <library.h>

#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	void *void_p_1[1];
	int int_0[1];
	my_struct *my_struct_p_1[1];
	int int_1[1];
	size_t size_t_0[1];
	char *char_p_0[1] = {"iyrbxokhucowvqzizlnh.bin"};
	size_t size_t_1[1];
	size_t size_t_2[1];
	void *void_p_0[1];
	my_struct *my_struct_p_0[1];
	memcpy(int_0, data, sizeof(int_0));data += sizeof(int_0);
	memcpy(int_1, data, sizeof(int_1));data += sizeof(int_1);
	memcpy(size_t_0, data, sizeof(size_t_0));data += sizeof(size_t_0);
	memcpy(size_t_1, data, sizeof(size_t_1));data += sizeof(size_t_1);
	//file init
	memcpy(size_t_2, data, sizeof(size_t_2));data += sizeof(size_t_2);
	FILE *p0 = fopen(char_p_0[0], "w");
	fwrite(data, 1, size_t_2[0], p0);
	fclose(p0);data += size_t_2[0];

	my_struct_p_0[0] =  create(char_p_0[0]);
	int_0[0] =  get_a(my_struct_p_0[0]);
	void_p_0[0] =  my_malloc(int_1[0]);
	my_free(void_p_0[0]);
	void_p_1[0] =  my_malloc(int_1[0]);
	my_free(void_p_1[0]);
	my_struct_p_0[0] =  create(char_p_0[0]);
	my_struct_p_1[0] =  create(char_p_0[0]);
	operation(my_struct_p_0[0]);
	operation(my_struct_p_0[0]);

	return 0;
}