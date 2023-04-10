#include<stdio.h>

int main(int argc, char** argv) {

    char *s0 = "ciao";
    printf("s0 = %s\n", s0);

    const char *s1 = "ciao";
    printf("s1 = %s\n", s1);

    const char s2[10] = "ok";
    // s2[0] = 'c';
    // s2[1] = 0;
    printf("s2 = %s\n", s2);

    return 0;
}