#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "library.h"

void edit(my_struct *s) {
	s->h = 10;
}

int xxsetup(my_struct *s) {
	s->a = 10;
	s->b = 10;
	s->c[0] = '0';
	return s->d;
}


static void fun1(my_struct *s) {

	xxsetup(s);
		// s->h = 10;
	edit(s);
	s->g = 5;
}

static void fun2(my_struct *s) {

	xxsetup(s);
		// s->h = 3;
	edit(s);
	s->i = 5;
}