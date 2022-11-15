
#include <stdlib.h>
#include <inttypes.h>

typedef struct strct STRCT;

struct strct {
	char*                name;         /* name of open file */
	int                  fd;           /* open file descriptor */
	uint32_t             flags;
};
int init_special_struct(STRCT* strct);
void pointer_free(void* p);
void write_name_in_file(STRCT* strct);
void close(STRCT* strct);