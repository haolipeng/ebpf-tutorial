#include <stdio.h>

__attribute__((noinline)) int uprobe_add(int a,int b)
{
    asm volatile ("");
    return a + b;
}


__attribute__((noinline)) int uprobe_sub(int a,int b)
{
    asm volatile ("");
    return a - b;
}

int main() {
    int result1 = uprobe_add(3, 5);
    printf("test_add(3, 5) = %d\n", result1);

    int result2 = uprobe_sub(10, 2);
    printf("test_sub(10, 2) = %d\n", result2);

    return 0;
}
