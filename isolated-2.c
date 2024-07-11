#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 10

void vulnerable_function(char* input) {
    char buffer[BUFFER_SIZE];
    size_t input_length = strlen(input);

    if (input_length >= BUFFER_SIZE) {
        printf("Input too large, potential buffer overflow!\n");
        return;
    }

    strcpy(buffer, input);  // Vulnerable strcpy function
    printf("Input copied into buffer: %s\n", buffer);
}

int main() {
    char input[] = "This is a long input that will cause buffer overflow";
    vulnerable_function(input);
    return 0;
}
