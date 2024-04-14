//go:build ignore

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    int iterations = 1000;  // 반복 횟수 설정

    printf("Calling getpid %d times...\n", iterations);
    for (int i = 0; i < iterations; ++i) {
        pid_t pid = syscall(SYS_getpid);  // getpid 시스템 호출 (syscall 사용)
        if (pid == -1) {
            perror("getpid");
            exit(EXIT_FAILURE);
        }
        printf("Iteration %d: Process ID (PID) = %d\n", i + 1, pid);
        // sleep(1);  // 1초 대기
    }

    printf("\nCompleted.\n");

    return 0;
}
