#include "library.h"
#include <stdio.h>

int nicolasFunc() {
	return 0;
};

int main(int argc, char* argv[]) {
	STRCT* s = malloc(sizeof(STRCT));
	init_special_struct(s);
	s->fd = fopen(s->name, "w");
	nicolasFunc();
	write_name_in_file(s);
	if(s) {
		close(s);
	} else {
		write_name_in_file(s);
		close(s);
	}
	return 0;
}
