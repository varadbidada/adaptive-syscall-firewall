#define _GNU_SOURCE
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

/* Helper macro */
#define ALLOW(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

struct sock_filter filter[] = {
    /* Load syscall number */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 0),

    /* ===== libc / loader required ===== */
    ALLOW(SYS_read),
    ALLOW(SYS_write),
    ALLOW(SYS_openat),
    ALLOW(SYS_close),
    ALLOW(SYS_fstat),
    ALLOW(SYS_brk),
    ALLOW(SYS_mmap),
    ALLOW(SYS_munmap),
    ALLOW(SYS_mprotect),
    ALLOW(SYS_exit_group),

    /* ===== BLOCK EVERYTHING ELSE ===== */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
};

int main() {
    /* Mandatory for seccomp */
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("seccomp");
        exit(1);
    }

    /* ===== Legitimate behavior ===== */
    int fd = open("data.txt", O_RDONLY);
    char buf[64];
    read(fd, buf, sizeof(buf));
    write(1, buf, sizeof(buf));
    close(fd);

    /* ===== Malicious behavior ===== */
    printf("\nAttempting network access...\n");
    socket(AF_INET, SOCK_STREAM, 0);   // ❌ BLOCKED HERE

    return 0;
}
