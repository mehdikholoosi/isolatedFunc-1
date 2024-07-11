#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 10

void vulnerable_function(char* input) {
    char buffer[BUFFER_SIZE];
    strcpy(buffer, input);  // Vulnerable strcpy function
    printf("Input copied into buffer: %s\n", buffer);
}

int main() {
    char input[] = "This is a long input that will cause buffer overflow";
    vulnerable_function(input);
    return 0;
}
