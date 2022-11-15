#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "library.h"


int init_special_struct(STRCT* strct) {
	strct->name = "hello.txt"; 
	strct->fd = 0;
	strct->flags = 0;
}

void pointer_free(void* p) {
   free(p);
}

void write_name_in_file(STRCT* strct) {
	fputs(strct->name, strct->fd);
	fputs("\n", strct->fd);
}

void close(STRCT* strct) {
	fclose(strct->fd);
}
