#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE_LENGTH 500
#define MAX_LABEL_LENGTH 50
#define MAX_INSTRUCTIONS 4096

// Data structures for storing instructions and labels
typedef struct {
    char label[MAX_LABEL_LENGTH];
    int address;
} Label;

typedef struct {
    char opcode[10];
    char rd[5], rs[5], rt[5], rm[5];
    char imm1[50], imm2[50];
} Instruction;

// Global variables
Label labels[MAX_INSTRUCTIONS];
int labelCount = 0;
Instruction instructions[MAX_INSTRUCTIONS];
int instructionCount = 0;

// Function prototypes
void trimWhitespace(char *str);
void parseInstruction(char *line, int address);
void firstPass(FILE *inputFile);
void secondPass(FILE *imeminFile, FILE *dmeminFile);
int getOpcode(const char *mnemonic);
int getRegister(const char *reg);
int resolveImmediate(const char *value);

// Helper function to trim whitespace
void trimWhitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

// Function to parse a single instruction
void parseInstruction(char *line, int address) {
    trimWhitespace(line);

    // Ignore empty lines and comments
    if (line[0] == '\0' || line[0] == '#') return;

    // Check for label
    char *colon = strchr(line, ':');
    if (colon) {
        *colon = '\0';
        strcpy(labels[labelCount].label, line);
        labels[labelCount++].address = address;
        line = colon + 1;
        trimWhitespace(line);
    }

    // Parse instruction or pseudo-instruction
    if (strncmp(line, ".word", 5) == 0) {
        // Handle .word directive
        char *token = strtok(line + 5, " ");
        int address = (int)strtol(token, NULL, 0);
        token = strtok(NULL, " ");
        int value = (int)strtol(token, NULL, 0);
        printf("Word directive: Address 0x%X, Value 0x%X\n", address, value); // Replace with actual handling
    } else {
        // Parse regular instruction
        Instruction instr;
        sscanf(line, "%s %[^,], %[^,], %[^,], %[^,], %[^,], %s",
               instr.opcode, instr.rd, instr.rs, instr.rt, instr.rm, instr.imm1, instr.imm2);
        instructions[instructionCount++] = instr;
    }
}

// First pass: Parse labels and instructions
void firstPass(FILE *inputFile) {
    char line[MAX_LINE_LENGTH];
    int address = 0;

    while (fgets(line, sizeof(line), inputFile)) {
        parseInstruction(line, address);
        address++;
    }
}

// Second pass: Resolve labels and generate machine code
void secondPass(FILE *imeminFile, FILE *dmeminFile) {
    for (int i = 0; i < instructionCount; i++) {
        Instruction *instr = &instructions[i];
        int opcode = getOpcode(instr->opcode); // Replace with opcode mapping
        int rd = getRegister(instr->rd);
        int rs = getRegister(instr->rs);
        int rt = getRegister(instr->rt);
        int rm = getRegister(instr->rm);
        int imm1 = resolveImmediate(instr->imm1); // Handle labels and numbers
        int imm2 = resolveImmediate(instr->imm2);

        // Encode instruction (48 bits)
        long long machineCode = ((long long)opcode << 40) |
                                ((long long)rd << 36) |
                                ((long long)rs << 32) |
                                ((long long)rt << 28) |
                                ((long long)rm << 24) |
                                ((long long)imm1 << 12) |
                                (long long)imm2;

        // Write to imemin.txt
        fprintf(imeminFile, "%012llX\n", machineCode);
    }

    // Write placeholder for data memory (dmemin.txt)
    for (int i = 0; i < 4096; i++) {
        fprintf(dmeminFile, "00000000\n");
    }
}

// Helper functions
int getOpcode(const char *mnemonic) {
    // Map mnemonics to opcodes
    if (strcmp(mnemonic, "add") == 0) return 0;
    if (strcmp(mnemonic, "sub") == 0) return 1;
    if (strcmp(mnemonic, "mac") == 0) return 2;
    if (strcmp(mnemonic, "and") == 0) return 3;
    if (strcmp(mnemonic, "or") == 0) return 4;
    if (strcmp(mnemonic, "xor") == 0) return 5;
    if (strcmp(mnemonic, "sll") == 0) return 6;
    if (strcmp(mnemonic, "sra") == 0) return 7;
    if (strcmp(mnemonic, "srl") == 0) return 8;
    if (strcmp(mnemonic, "beq") == 0) return 9;
    if (strcmp(mnemonic, "bne") == 0) return 10;
    if (strcmp(mnemonic, "blt") == 0) return 11;
    if (strcmp(mnemonic, "ble") == 0) return 12;
    if (strcmp(mnemonic, "bge") == 0) return 13;
    if (strcmp(mnemonic, "jal") == 0) return 15;
    if (strcmp(mnemonic, "lw") == 0) return 16;
    if (strcmp(mnemonic, "sw") == 0) return 17;
    if (strcmp(mnemonic, "reti") == 0) return 18;
    if (strcmp(mnemonic, "in") == 0) return 19;
    if (strcmp(mnemonic, "out") == 0) return 20;
    if (strcmp(mnemonic, "halt") == 0) return 21;
    return -1;
}

int getRegister(const char *reg) {
    // Map register names to numbers
    if (strcmp(reg, "$zero") == 0) return 0;
    if (strcmp(reg, "$imm1") == 0) return 1;
    if (strcmp(reg, "$imm2") == 0) return 2;
    if (strcmp(reg, "$t0") == 0) return 7;
    if (strcmp(reg, "$t1") == 0) return 8;
    if (strcmp(reg, "$t2") == 0) return 9;
    if (strcmp(reg, "$ra") == 0) return 15;
    return -1;
}

int resolveImmediate(const char *value) {
    // Handle decimal, hexadecimal, and labels
    if (isdigit(value[0]) || value[0] == '-') {
        return atoi(value);
    } else if (strncmp(value, "0x", 2) == 0) {
        return (int)strtol(value, NULL, 16);
    } else {
        for (int i = 0; i < labelCount; i++) {
            if (strcmp(labels[i].label, value) == 0) {
                return labels[i].address;
            }
        }
    }
    return 0; // Default case
}

// Main function
int main(/*int argc, char *argv[] */) {
    // if (argc != 4) {
    //     printf("Usage: %s program.asm imemin.txt dmemin.txt\n", argv[0]);
    //     return 1;
    // }

    // FILE *inputFile = fopen(argv[1], "r");
    // FILE *imeminFile = fopen(argv[2], "w");
    // FILE *dmeminFile = fopen(argv[3], "w");

    // if (!inputFile || !imeminFile || !dmeminFile) {
    //     printf("Error opening files.\n");
    //     return 1;
    // }

    FILE *inputFile = fopen("fib.asm", "r");
    FILE *imeminFile = fopen("imemin.txt", "w");
    FILE *dmeminFile = fopen("dmemin.txt", "w");

    if (inputFile == NULL || imeminFile == NULL || dmeminFile == NULL) {
        printf("Error opening files.\n");
        return 1;
    }


    // First and second passes
    firstPass(inputFile);
    rewind(inputFile); // Reset file pointer for second pass
    secondPass(imeminFile, dmeminFile);

    fclose(inputFile);
    fclose(imeminFile);
    fclose(dmeminFile);

    return 0;
}
