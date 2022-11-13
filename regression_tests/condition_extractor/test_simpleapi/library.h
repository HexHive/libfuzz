
#include <stdlib.h>
#include <inttypes.h>

typedef struct a_struct my_struct;

my_struct* create(int a, int b);
void first(my_struct *s, int a);
void second(my_struct *s, int b);
void close(my_struct *s);