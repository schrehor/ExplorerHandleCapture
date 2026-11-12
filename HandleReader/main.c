#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <EXPLORER_PID> <RSP_SLOT_ADDRESS_HEX>\n", argv[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}