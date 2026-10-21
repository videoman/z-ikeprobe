/* nmiprobe.c - raw AF_UNIX probe for z/OS IKED NMI (or any unix socket)
 *
 * Sends arbitrary bytes (given as hex on the command line) to a UNIX
 * domain socket and hexdumps whatever comes back, with an EBCDIC
 * (native) text column.  No IBM NMI headers required.
 *
 * Build:  c89 -o nmiprobe nmiprobe.c        (or: xlc -o nmiprobe nmiprobe.c)
 *
 * Usage:  nmiprobe <sockpath> [hexbytes|-] [padlen] [timeout_sec]
 *   hexbytes  bytes to send, e.g. D5D4A287 (spaces/colons not allowed)
 *             "-" = send nothing, just listen for a greeting
 *   padlen    zero-pad the request out to this many bytes
 *   timeout   seconds to wait for reply data (default 5)
 *
 * Examples:
 *   nmiprobe /var/ike/iked.sock -                  # listen only
 *   nmiprobe /var/ike/iked.sock 00 64              # 64 zero bytes
 *   nmiprobe /var/ike/iked.sock D5D4A287 64        # eyecatcher + pad
 */
#define _XOPEN_SOURCE_EXTENDED 1
#define _OE_SOCKETS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#define MAXBUF 65536

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = toupper(c);
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void dump(const unsigned char *p, long n, long base)
{
    long i, j;
    for (i = 0; i < n; i += 16) {
        printf("%08lX  ", base + i);
        for (j = 0; j < 16; j++) {
            if (i + j < n) printf("%02X", p[i + j]);
            else           printf("  ");
            if (j % 4 == 3) printf(" ");
        }
        printf(" |");
        for (j = 0; j < 16 && i + j < n; j++)   /* native = EBCDIC on z/OS */
            putchar(isprint(p[i + j]) ? p[i + j] : '.');
        printf("|\n");
    }
}

int main(int argc, char **argv)
{
    struct sockaddr_un sa;
    static unsigned char req[MAXBUF], rsp[MAXBUF];
    long reqlen = 0, padlen = 0, total = 0;
    int fd, timeout = 5, rc;
    const char *hex;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <sockpath> [hexbytes|-] [padlen] [timeout]\n",
                argv[0]);
        return 2;
    }
    hex = (argc > 2) ? argv[2] : "-";
    if (argc > 3) padlen  = atol(argv[3]);
    if (argc > 4) timeout = atoi(argv[4]);

    if (strcmp(hex, "-") != 0) {
        size_t k, L = strlen(hex);
        if (L % 2) { fprintf(stderr, "odd number of hex digits\n"); return 2; }
        for (k = 0; k < L; k += 2) {
            int hi = hexval(hex[k]), lo = hexval(hex[k + 1]);
            if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex at %lu\n",
                                            (unsigned long)k); return 2; }
            req[reqlen++] = (unsigned char)((hi << 4) | lo);
        }
    }
    if (padlen > MAXBUF) padlen = MAXBUF;
    if (padlen > reqlen) reqlen = padlen;          /* req[] is zeroed */

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, argv[1], sizeof sa.sun_path - 1);

    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        fprintf(stderr, "connect(%s): %s (errno %d)\n",
                argv[1], strerror(errno), errno);
        return 1;
    }
    printf("[+] connected to %s\n", argv[1]);

    if (reqlen > 0) {
        long off = 0;
        while (off < reqlen) {
            rc = send(fd, req + off, reqlen - off, 0);
            if (rc < 0) { perror("send"); return 1; }
            off += rc;
        }
        printf("[>] sent %ld bytes:\n", reqlen);
        dump(req, reqlen, 0);
    }

    for (;;) {
        struct pollfd pf;
        pf.fd = fd; pf.events = POLLIN; pf.revents = 0;
        rc = poll(&pf, 1, timeout * 1000);
        if (rc == 0) { printf("[*] timeout after %ds\n", timeout); break; }
        if (rc < 0)  { perror("poll"); break; }
        rc = recv(fd, rsp, sizeof rsp, 0);
        if (rc == 0) { printf("[*] peer closed connection\n"); break; }
        if (rc < 0)  { fprintf(stderr, "recv: %s (errno %d)\n",
                               strerror(errno), errno); break; }
        printf("[<] recv %d bytes (offset %ld):\n", rc, total);
        dump(rsp, rc, total);
        total += rc;
    }
    printf("[*] total received: %ld bytes\n", total);
    close(fd);
    return 0;
}
