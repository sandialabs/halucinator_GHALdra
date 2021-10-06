// Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
// Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains 
// certain rights in this software.

#include <stdio.h>
#include <time.h>

#define ADD_OUT_FLAGS(out_var, inval1, inval2) out_var = inval1 + inval2;
#define SUB_OUT_FLAGS(out_var, inval1, inval2) out_var = inval1 - inval2;
#define UPDATE_MANY_REGS(retval) retval = 2

__attribute__ ((__noinline__))
void * get_pc () { 
    return __builtin_return_address(0); 
}

long int simple_adds(int inval) {
    return inval + inval;
}

int big_sub(int inval) {
    return inval - 0x7fffffff;
}

long int another_sub(long int inval1, long int inval2) {
    return inval1 - inval2;
}

long int investigate_add_flags(int invala, int invalb) {
    long int retval = 0;
    ADD_OUT_FLAGS(retval, invala, invalb);
    return retval;
}

long int investigate_sub_flags(int invala, int invalb) {
    long int retval = 0;
    SUB_OUT_FLAGS(retval, invala, invalb);
    return retval;
}

long int div(long int invala, long int invalb) {
    return invala / invalb;
}

unsigned long int unsign_div(unsigned long int invala,
        unsigned long int invalb) {
    return invala / invalb;
}

long int sub_if(int inval) {
    if( inval - 1 > 0 ) {
        return 0;
    } else {
        return 1;
    }
}

long unsigned int update_many_regs(long int inval) {
    long unsigned int retval = 0;
    UPDATE_MANY_REGS(retval);
    return retval;
}

void try_print_simple_adds(int val) {
    printf("Simple adds %x result %lx\n", val, simple_adds(val));
}

float float_test(float float1, float float2) {
    return float1 + float2;
}

double double_test(double double1, double double2) {
    return double1 + double2;
}

int try_sleep(time_t secs, long nanosecs) {
    struct timespec sleep_len = { 0 }, rem = { 0 };
    int retval = -1, tries = 0;
    sleep_len.tv_sec = secs;
    sleep_len.tv_nsec = nanosecs;
    while( retval != 0 ) {
        tries += 1;
        retval = nanosleep(&sleep_len, &rem);
        sleep_len.tv_sec = rem.tv_sec;
        sleep_len.tv_nsec = rem.tv_nsec;
    }
    return tries;
}

int main() {
    try_print_simple_adds(0x10001000);
    try_print_simple_adds(0x20002000);
    try_print_simple_adds(0x60006000);
    try_print_simple_adds(0x80008000);
    try_print_simple_adds(0xd000d000);
    printf("PC: %p\n", get_pc());
    
    printf("Another sub 0x%lx\n", another_sub(0x10, 0x40));

    int test_val = 0x7fffffff;

    printf("Investigate add flags 0x%x 0x%lx\n", test_val, investigate_add_flags(test_val, test_val));

    test_val = 0x0;
    int test_val_2 = 0x80000001;

    printf("Investigate sub flags 0x%x 0x%x 0x%lx\n", test_val, test_val_2, investigate_sub_flags(test_val, test_val_2));

    printf("Big sub 1 %i\n", big_sub(1));
    printf("Big sub 0 %i\n", big_sub(0));
    printf("Big sub -1 %i\n", big_sub(-1));
    printf("Big sub -2 %i\n", big_sub(-2));
    printf("Big sub 0x80000001 %i\n", big_sub(0x80000001));
    printf("Big sub 0x80000000 %i\n", big_sub(0x80000000));
    printf("Big sub 0x7fffffff %i\n", big_sub(0x7fffffff));

    printf("Flags: C1Px AxZS TIDO\n");

    printf("Div result 10/2 %li\n", div(10, 2));
    printf("Unsigned div result 10 / 2 %li\n", unsign_div(10, 2));
    printf("Div result -10/2 %li\n", div(-10, 2));
    printf("Unsigned div result -10 / 2 %li\n", unsign_div(-10, 2));

    float f_a = 1.1, f_b = 2.2;
    printf("Float test %f + %f = %f\n", f_a, f_b, float_test(f_a, f_b));

    double d_a = 1.1, d_b = 2.2;
    printf("Double test %f + %f = %f\n", d_a, d_b, double_test(d_a, d_b));

    return 0;
}
