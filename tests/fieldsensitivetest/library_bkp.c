#include "library.h"
#include <stdio.h>
#include <string.h>

// my_struct* my_producer(int a, int b, int c) {
//     my_struct *s = malloc(sizeof(my_struct));

//     s->field_a = a;
//     s->field_b = b;
//     s->field_c = c;

//     return s;
// }

// my_struct* my_producer_empty() {
//     my_struct *s = malloc(sizeof(my_struct));

//     return s;
// }

// void my_ab_set(my_struct* s, int a, int b) {
//     s->field_a = a;
//     s->field_b = b;
// }

// void my_c_set(my_struct* s,int c) {
//     s->field_c = c;
// }

// void inner_fun1(my_struct* s, int c) {
//     s->field_c = c;
// }

// void inner_fun2(my_struct* s, int c) {
//     s->field_a = c;
// }

// void (*fun_ptr)(my_struct*,int) = inner_fun2;


// typedef struct my_struct {
//     int field_b;
//     int field_c;
// } my_struct;

// void fun(my_struct* s) {

//     int t;
//     t = s->field_b;
//     s->field_b = s->field_c;
//     s->field_c = t;

//     s->sub_struct = a;

//     s->sub_struct->field_sa = s->sub_struct->field_sb + 10;
// }

void aaa(my_struct* s) {
    s->a = 10;
}
// void bbb(my_struct* s) {
//     s->b = 1;
//     aaa(s);
// }

// void fun2(my_struct *s) {
//     bbb(s);
// }


void my_memset(my_struct* dst, int x, size_t len) {
    memset(dst, x, len);
}

my_struct* create_struct(char* s) {
    my_struct *ss = (my_struct *) malloc(sizeof(my_struct)  + strlen(s) + 1);
    my_memset(ss, 0, sizeof(*ss));
    ss->c = (char *)ss + sizeof(my_struct);
	strcpy(ss, s);
    // ss = s;
    ss->a = 10;
    ss->b = 10;
    ss->cc = 10;
    ss->d = 10;
    return ss;
}


void fun2(char*s) {
    my_struct *ss = create_struct(s);
    ss->b = 10;
}


void fun1(char* s) {

    // void (*fun_ptr)(my_struct*) = NULL;

    // if (x)
    //     fun_ptr = &aaa;
    // else
    //     fun_ptr = &bbb;

    
    my_struct *ss = create_struct(s);
    
    // void *x = ss;

    // my_memset(x, 0, sizeof(*ss));

    // tif->tif_name = (char *)tif + sizeof (TIFF);
	
	ss->a = 10;

}


// void alias_test(my_struct* s1, my_struct* s2, int c) {

//     my_struct *s;

//     if (c > 10)
//         s = s1;
//     else
//         s = s2;

//     s->field_c = c;
// }

// int my_c_get(my_struct* s) {
//     return s->field_c;
// }

// void my_bc_set(my_struct* s, int b, int c) {
//     s->field_b = b;
//     s->field_c = c;
// }

// void my_fullycopy(my_struct* s1, my_struct* s2) {
//     s1->field_a = s2->field_a;
//     s1->field_b = s2->field_b;
//     s1->field_c = s2->field_c;
// }

// void my_partialcopy(my_struct* s1, my_struct* s2) {
//     s1->field_a = s2->field_a;
//     // I don't copy field_b on purpose 
//     s1->field_c = s2->field_c;
// }

// void my_destroyer(my_struct* s) {
//     free(s);
// }