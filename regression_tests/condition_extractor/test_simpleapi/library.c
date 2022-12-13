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
};

void bar() {
	// return 1;
}

void foo(int a) {
	int x = 0;
	if (a > 0)
		// x = 10;
		bar();
	else
		// x = 11;
		bar();
	return;
}

void my_free(my_struct* s) {
	free(s);
}

my_struct* create(int a, int b) {
	my_struct *s = (my_struct*)malloc(sizeof(my_struct));

	if (a == 0) {
		my_free(s);
		return 0;
	}

	if (b <= 0) {
		my_free(s);
		return 0;
	}

	s->field_a = a;
	s->field_b = b;

	return s;
}

void first(my_struct *s, int a) {
	s->field_a = a;
	if (s->field_a < 0)
		s->field_a = -s->field_a;
}

void second(my_struct *s, int b) {
	if (s->field_a > 10)
		s->field_b = b;
}

void third(void* b, my_struct *s) {
	s->field_a = (int)b;
}

void close(my_struct *s) {
	if (s != NULL)
		my_free(s);
}