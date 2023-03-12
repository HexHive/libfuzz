#include <library.h>

#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {
	size_t size_t_s0[1];
	char *char_p_s0 = "hwhaqxubxktwmaxaqeeq.bin";
	size_t size_t_s2[1];
	char char_p_s1[128];
	size_t size_t_s1[1];
	char *char_p_s2 = "xvltxpbzkkotcrholbnz.bin";
	int int_s2[1];
	void *void_p_h0[1];
	my_struct *my_struct_p_h0[1];
	int int_s0[1];
	int int_s1[1];
	memcpy(size_t_s0, data, sizeof(size_t_s0));data += sizeof(size_t_s0);
	memcpy(char_p_s1, data, sizeof(char_p_s1));data += sizeof(char_p_s1);
	memcpy(int_s2, data, sizeof(int_s2));data += sizeof(int_s2);
	memcpy(int_s0, data, sizeof(int_s0));data += sizeof(int_s0);
	memcpy(int_s1, data, sizeof(int_s1));data += sizeof(int_s1);
	//file init
	memcpy(size_t_s1, data, sizeof(size_t_s1));data += sizeof(size_t_s1);
	FILE *p0 = fopen(char_p_s0[0], "w");
	fwrite(data, 1, size_t_s1[0], p0);
	fclose(p0);data += size_t_s1[0];

	//file init
	memcpy(size_t_s2, data, sizeof(size_t_s2));data += sizeof(size_t_s2);
	FILE *p1 = fopen(char_p_s2[0], "w");
	fwrite(data, 1, size_t_s2[0], p1);
	fclose(p1);data += size_t_s2[0];

	void_p_h0[0] =  my_malloc(int_s0[0]);
	if (void_p_h0[0] == 0) return 0;
	my_free(void_p_h0[0]);
	my_struct_p_h0[0] =  create(char_p_s0);
	if (my_struct_p_h0[0] == 0) return 0;
	my_struct_p_h0[0] =  create(char_p_s0);
	if (my_struct_p_h0[0] == 0) return 0;
	get_data(my_struct_p_h0[0], char_p_s1);
	my_struct_p_h0[0] =  create(char_p_s2);
	if (my_struct_p_h0[0] == 0) return 0;
	operation(my_struct_p_h0[0]);
	int_s1[0] =  get_a(my_struct_p_h0[0]);
	set_b(my_struct_p_h0[0], int_s2[0]);
	set_b(my_struct_p_h0[0], int_s2[0]);

	return 0;
}