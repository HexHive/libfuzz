#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "library.h"

void another_init(my_struct *m) {
	m->cc = 10;
	m->i = 5;
}

my_struct* my_malloc() {
	return (my_struct*)malloc(sizeof(my_struct));
}

my_struct* create_struct(uint64_t aa, uint64_t bb) {

	if (aa == 0 || bb == 1)
		return NULL;

	my_struct *m = my_malloc();

	another_init(m);

	m->a = aa;
	m->b = bb;

	return m;

}

my_struct* create_default_struct() {

	my_struct *m = create_struct(10, 5);

	another_init(m);

	return m;
}