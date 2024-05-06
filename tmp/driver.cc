#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>



extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    if (data[0] == 'A')
	    printf("you got A\n");
    if (data[0] == 'B')
	    printf("you got B\n");
    if (data[0] == 'D')
	    printf("you got C\n");
    if (data[0] == 'D')
	    printf("you got D\n");

    printf("nothing :(\n");

	return 0;
}