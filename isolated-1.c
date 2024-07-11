#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

char* get_dynamic_memory(size_t size) {
    char *ptr = (char*)malloc(size);
    if (!ptr) {
        printf("Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

void process_data(char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] = (data[i] ^ 0x5A);
    }
}

void handle_user_input(char* buffer) {
    printf("Enter data: ");
    if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
        printf("Error reading input\n");
        exit(1);
    }
    buffer[strcspn(buffer, "\n")] = '\0';
}

void manipulate_data(char* buffer) {
    size_t length = strlen(buffer);
    char *dynamic_buffer = get_dynamic_memory(length + 1);
    strcpy(dynamic_buffer, buffer);
    process_data(dynamic_buffer, length);

    char *temp_buffer = get_dynamic_memory(length + 1);
    strcpy(temp_buffer, dynamic_buffer);
    printf("Processed data: %s\n", temp_buffer);
    free(temp_buffer);
    
    // Deliberately use dynamic_buffer after freeing temp_buffer
    // to make the use-after-free more obvious
    if (length > 5) { 
        printf("Reprocessed data: %s\n", dynamic_buffer);
    }

    free(dynamic_buffer);
}

void perform_operations() {
    char static_buffer[BUFFER_SIZE];
    handle_user_input(static_buffer);
    
    manipulate_data(static_buffer);

    printf("Operations complete\n");
}

int main() {
    perform_operations();
    return 0;
}
