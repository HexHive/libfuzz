#include "myLib.hpp"
#include <iostream>

using namespace std;

#define INIT 0
#define START 1
#define STOP 2

int STATE = INIT;

void print_value( int x )
{
    cout << x << "\n";
}

void set_state(int x) {
    STATE=x;
}

int get_state() {
    return STATE;
}

void leak() {

}

int taint() {
    // leak();
    return 10;
}

void startservice() {
    if (get_state() == START)
        return;

    set_state(START);

    int x = taint();
}

void stopservice() {
    if (get_state() == START)
        return;

    set_state(INIT);
}

int getservicestate() {
    return get_state();
}



// int foo() {
//     int a = 10;
//     int b = a + 3;

//     if (a > 3)
//         b = a * 2;
//     else
//         b = a - 4;

//     return b;
// }
