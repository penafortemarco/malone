// target.c
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("This is process %d\n", getpid());    
    while(1) {
        sleep(1);
        printf("Im just a naive process...\n");
    }
    return 0;
}