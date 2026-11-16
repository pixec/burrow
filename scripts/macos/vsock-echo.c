/*
 * Checks that a macOS guest exposes AF_VSOCK to userspace: listens on a vsock
 * port, prints the local CID, and echoes each connection back with a greeting
 * so the host side can tell it reached this process.
 *
 *   cc -O2 -o vsock-echo vsock-echo.c && ./vsock-echo [port]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/vsock.h>

int main(int argc, char **argv) {
    unsigned port = argc > 1 ? (unsigned)atoi(argv[1]) : 1024;
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket(AF_VSOCK)"); return 1; }
    uint32_t cid = 0;
    if (ioctl(fd, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid) < 0) perror("get local cid");
    struct sockaddr_vm addr = {
        .svm_len = sizeof addr, .svm_family = AF_VSOCK,
        .svm_port = port, .svm_cid = VMADDR_CID_ANY,
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(fd, 16) < 0) { perror("listen"); return 1; }
    printf("listening on vsock cid %u port %u\n", cid, port);
    fflush(stdout);
    for (;;) {
        struct sockaddr_vm peer; socklen_t len = sizeof peer;
        int c = accept(fd, (struct sockaddr *)&peer, &len);
        if (c < 0) { perror("accept"); continue; }
        char hello[96];
        int n = snprintf(hello, sizeof hello, "hello from macos guest pid %d, peer cid %u port %u\n",
                         getpid(), peer.svm_cid, peer.svm_port);
        write(c, hello, (size_t)n);
        char buf[4096];
        ssize_t r;
        while ((r = read(c, buf, sizeof buf)) > 0) write(c, buf, (size_t)r);
        close(c);
    }
}
