#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    static const unsigned char encoded[] = {
        0x28, 0x69, 0x2c, 0x05, 0x6b, 0x29,
        0x05, 0x3c, 0x2f, 0x34, 0x7b,
    };
    const size_t answer_length = sizeof(encoded) / sizeof(encoded[0]);

    if (argc != 2 || strlen(argv[1]) != answer_length) {
        puts("not yet");
        return 1;
    }

    for (size_t index = 0; index < answer_length; index++) {
        if (((unsigned char)argv[1][index] ^ 0x5aU) != encoded[index]) {
            puts("not yet");
            return 1;
        }
    }

    puts("accepted");
    return 0;
}
