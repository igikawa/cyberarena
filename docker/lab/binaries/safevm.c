#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define MAX_HEX_LENGTH 64U
#define MAX_PROGRAM_BYTES (MAX_HEX_LENGTH / 2U)
#define TARGET_STATE 0x2aU

static int hex_value(char character) {
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static bool decode_program(
    const char *input,
    unsigned char program[MAX_PROGRAM_BYTES],
    size_t *program_length
) {
    size_t input_length = strlen(input);

    if (input_length == 0U || input_length > MAX_HEX_LENGTH ||
        input_length % 2U != 0U) {
        return false;
    }

    *program_length = input_length / 2U;
    for (size_t index = 0; index < *program_length; index++) {
        int high = hex_value(input[index * 2U]);
        int low = hex_value(input[index * 2U + 1U]);
        if (high < 0 || low < 0) {
            return false;
        }
        program[index] = (unsigned char)((unsigned int)high * 16U +
                                         (unsigned int)low);
    }
    return true;
}

static bool execute_program(
    const unsigned char program[MAX_PROGRAM_BYTES],
    size_t program_length
) {
    unsigned int state = 0x13U;
    size_t instruction_count = 0U;

    for (size_t pc = 0U; pc < program_length;) {
        unsigned char opcode = program[pc++];
        instruction_count++;

        if (opcode == 0xfeU) {
            return pc == program_length && instruction_count >= 3U &&
                   state == TARGET_STATE;
        }
        if (pc >= program_length) {
            return false;
        }

        unsigned int operand = program[pc++];
        switch (opcode) {
            case 0x20U:
                state ^= operand;
                break;
            case 0x30U:
                state = (state + operand) & 0xffU;
                break;
            case 0x40U:
                if (operand == 0U || operand > 7U) {
                    return false;
                }
                state = ((state << operand) | (state >> (8U - operand))) & 0xffU;
                break;
            default:
                return false;
        }
    }
    return false;
}

int main(int argc, char **argv) {
    unsigned char program[MAX_PROGRAM_BYTES];
    size_t program_length = 0U;

    if (argc != 2 ||
        !decode_program(argv[1], program, &program_length) ||
        !execute_program(program, program_length)) {
        puts("locked");
        return 1;
    }

    puts("state reached");
    return 0;
}
