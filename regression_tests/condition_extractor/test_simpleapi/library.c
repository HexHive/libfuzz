#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "library.h"

struct a_struct {
    int field_a;
    int field_b;
	int field_c;
	int field_d;
};

void bar1() {
	// return 1;
}

void bar2() {
	// return 1;
}


void foo(int a) {
	int x = 0;
	if (a > 0)
		// x = 10;
		bar1();
	else
		// x = 11;
		bar1();
	return;
}

void my_free(my_struct* s) {
	free(s);
}

void* my_malloc(size_t s) {
	if (s == 0)
		return NULL;

	return malloc(s);
}

void indirect_test(my_struct *s, int a) {

	void (*fun_ptr)(my_struct*,int) = NULL;
	if (a > 0)
		fun_ptr = &first;
	else 
		fun_ptr = &second;

	fun_ptr(s, a);

	s->field_a = 10;
	s->field_b = 11;

	my_free(s);
}

my_struct* create(int a, int b) {
	my_struct *s = my_malloc(sizeof(my_struct));

	if (s == NULL) {
		return NULL;
	}

	if (a == 0) {
		my_free(s);
		return 0;
	}

	s->field_a = a;
	s->field_b = b;
	
	my_struct *s1 = my_malloc(sizeof(my_struct));

	// int xx[10];
	// for (int i = 0; i < 10; i++) {
	// 	if (i > 5)
	// 		xx[i] = i + 1;
	// 	else 
	// 		xx[i] = i * 2;
	// }

	return s;
}

void first(my_struct *s, int a) {
	s->field_b = a;
	if (s->field_c < 0)
		s->field_c = -s->field_c;
}

void second(my_struct *s, int b) {
	if (s->field_a > 10)
		s->field_d = b;
}

void third(void* b, my_struct *s) {
	s->field_a = (int)b;
}

void close(my_struct *s) {
	if (s != NULL)
		my_free(s);
}