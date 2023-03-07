#include <library.h>

#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	void *void_p_2[1];
	int int_0[1];
	my_struct *my_struct_p_0[1];
	int int_2[1];
	char char_p_0[1][1];
	void *void_p_1[1];
	void *void_p_0[1];
	int int_1[1];
	memcpy(int_0, data, sizeof(int_0));data += sizeof(int_0);
	memcpy(int_2, data, sizeof(int_2));data += sizeof(int_2);
	memcpy(char_p_0, data, sizeof(char_p_0));data += sizeof(char_p_0);
	memcpy(int_1, data, sizeof(int_1));data += sizeof(int_1);
	void_p_0[0] =  my_malloc(int_0[0]);
	my_free(void_p_0[0]);
	my_struct_p_0[0] =  create(char_p_0[0]);
	operation(NULL);
	set_a(my_struct_p_0[0], int_1[0]);
	int_1[0] =  get_b(NULL);
	void_p_1[0] =  my_malloc(int_2[0]);
	my_free(void_p_1[0]);
	void_p_2[0] =  my_malloc(int_0[0]);
	my_free(void_p_2[0]);

	return 0;
}