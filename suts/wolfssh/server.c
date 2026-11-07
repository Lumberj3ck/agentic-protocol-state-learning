/* B1 adaptation of vendor/agentic-protocol-state-learning/targets/wolfssh/server.c (Apache-2.0):
   user tester, password + publickey (/etc/psm/authorized_keys), RSA host key.
   Minimal test server; protocol handling belongs entirely to wolfSSH. */
#include <wolfssl/options.h>
#include <wolfssh/ssh.h>
#include <wolfssh/error.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int b64v(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static int b64dec(const char* in, unsigned char* out, int max) {
    int n = 0, acc = 0, bits = 0;
    for (; *in; in++) {
        int v = b64v((unsigned char)*in);
        if (v < 0) continue;
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; if (n < max) out[n++] = (acc >> bits) & 0xff; }
    }
    return n;
}
static int key_authorized(const byte* blob, word32 blobSz) {
    FILE* f = fopen("/etc/psm/authorized_keys", "r");
    char line[8192];
    unsigned char dec[8192];
    int ok = 0;
    if (!f) return 0;
    while (!ok && fgets(line, sizeof line, f)) {
        char *save = NULL, *t = strtok_r(line, " \t\r\n", &save), *b = strtok_r(NULL, " \t\r\n", &save);
        if (!t || !b) continue;
        int n = b64dec(b, dec, sizeof dec);
        ok = (n > 0 && (word32)n == blobSz && memcmp(dec, blob, blobSz) == 0);
    }
    fclose(f);
    return ok;
}
static int auth(byte type, WS_UserAuthData* d, void* ctx) {
    (void)ctx;
    int user_ok = d->usernameSz == 6 && memcmp(d->username, "tester", 6) == 0;
    if (type == WOLFSSH_USERAUTH_PUBLICKEY)
        return user_ok && key_authorized(d->sf.publicKey.publicKey, d->sf.publicKey.publicKeySz)
            ? WOLFSSH_USERAUTH_SUCCESS : WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
    if (type != WOLFSSH_USERAUTH_PASSWORD)
        return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
    return user_ok && d->sf.password.passwordSz == 21 &&
        memcmp(d->sf.password.password, "correct-horse-battery", 21) == 0
        ? WOLFSSH_USERAUTH_SUCCESS : WOLFSSH_USERAUTH_FAILURE;
}
static int auth_types(WOLFSSH* ssh, void* ctx) {
    (void)ssh; (void)ctx;
    return WOLFSSH_USERAUTH_PASSWORD | WOLFSSH_USERAUTH_PUBLICKEY;
}
static int exec_request(WOLFSSH_CHANNEL* channel, void* ctx) {
    (void)channel;
    *(int*)ctx = 1;
    return WS_SUCCESS;
}
static void serve(WOLFSSH_CTX* ctx, int fd) {
    WOLFSSH* ssh = wolfSSH_new(ctx);
    int done = 0;
    if (!ssh) return;
    wolfSSH_set_fd(ssh, fd);
    wolfSSH_SetChannelReqCtx(ssh, &done);
    if (wolfSSH_accept(ssh) == WS_SUCCESS) {
        for (;;) {
            word32 id;
            int rc = wolfSSH_worker(ssh, &id);
            if (done) {
                wolfSSH_stream_exit(ssh, 0);
                break;
            }
            if (rc == WS_SUCCESS || rc == WS_CHAN_RXD ||
                rc == WS_CHANNEL_CLOSED || rc == WS_REKEYING ||
                rc == WS_EOF || rc == WS_WANT_READ || rc == WS_WANT_WRITE) continue;
            break;
        }
    }
    wolfSSH_free(ssh);
}
int main(void) {
    unsigned char key[4096];
    FILE* f = fopen("host-key.pem", "rb");
    if (!f) return 1;
    size_t size = fread(key, 1, sizeof(key), f);
    fclose(f);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    wolfSSH_Init();
    WOLFSSH_CTX* ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (!ctx || wolfSSH_CTX_UsePrivateKey_buffer(ctx, key, size,
            WOLFSSH_FORMAT_PEM) != WS_SUCCESS) return 1;
    wolfSSH_SetUserAuth(ctx, auth);
    wolfSSH_SetUserAuthTypes(ctx, auth_types);
    wolfSSH_CTX_SetAppChannels(ctx, 1);
    wolfSSH_CTX_SetChannelReqExecCb(ctx, exec_request);
    int listener = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr = {.sin_family = AF_INET,
        .sin_port = htons(22), .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) ||
            listen(listener, 32)) return 1;
    for (;;) {
        int fd = accept(listener, NULL, NULL);
        if (fd < 0) continue;
        pid_t pid = fork();
        if (pid == 0) {
            close(listener);
            serve(ctx, fd);
            close(fd);
            _exit(0);
        }
        close(fd);
    }
}
