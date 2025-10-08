#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>

int main() {
    printf("Generating high-frequency getpid() calls...\n");

    while (1) {
        // 每次循环调用 10000 次 getpid()
        for (int i = 0; i < 10000; i++) {
            getpid();
        }
    }

    return 0;
}
