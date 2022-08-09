#include <stdio.h>

typedef enum _my_enum {FIRST, SECOND, THIRD} MyEnum;

int main(int arch, char** argv) {

    printf("FIRST < SECOND %d\n", (FIRST < SECOND));
    printf("SECOND < THIRD %d\n", (SECOND < THIRD));
    printf("FIRST < THIRD %d\n", (FIRST < THIRD));
    printf("THIRD < FIRST %d\n", (THIRD < FIRST));

    return 0;
}