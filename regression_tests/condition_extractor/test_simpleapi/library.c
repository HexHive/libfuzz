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

my_struct* create(int a, int b) {
	my_struct *s = (my_struct*)malloc(sizeof(my_struct));
	return s;
}

void first(my_struct *s, int a) {
	s->field_a = a;
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
		free(s);
}