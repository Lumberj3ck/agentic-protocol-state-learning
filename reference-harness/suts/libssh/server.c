/* B1 adaptation of vendor/agentic-protocol-state-learning/targets/libssh/server.c (Apache-2.0):
   user tester, password + publickey, RSA + Ed25519 host keys.
   Minimal test server: libssh owns transport, authentication and channel framing. */
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct channel {
    ssh_channel handle;
    int exec_pending;
    struct ssh_channel_callbacks_struct callbacks;
    struct channel *next;
};
struct connection {
    int authenticated;
    struct channel *channels;
};

static int password(ssh_session s, const char *user, const char *pass, void *data)
{
    (void)s;
    struct connection *c = data;
    if (strcmp(user, "tester") || strcmp(pass, "correct-horse-battery")) return SSH_AUTH_DENIED;
    c->authenticated = 1;
    return SSH_AUTH_SUCCESS;
}
static int key_authorized(ssh_key pubkey)
{
    FILE *f = fopen("/etc/psm/authorized_keys", "r");
    char line[8192];
    int ok = 0;
    if (!f) return 0;
    while (!ok && fgets(line, sizeof line, f)) {
        char *save = NULL, *type = strtok_r(line, " \t\r\n", &save), *b64 = strtok_r(NULL, " \t\r\n", &save);
        if (!type || !b64) continue;
        enum ssh_keytypes_e kt = ssh_key_type_from_name(type);
        ssh_key k = NULL;
        if (ssh_pki_import_pubkey_base64(b64, kt, &k) == SSH_OK) {
            ok = ssh_key_cmp(k, pubkey, SSH_KEY_CMP_PUBLIC) == 0;
            ssh_key_free(k);
        }
    }
    fclose(f);
    return ok;
}
static int auth_pubkey(ssh_session s, const char *user, struct ssh_key_struct *pubkey,
                       char signature_state, void *data)
{
    (void)s;
    struct connection *c = data;
    if (strcmp(user, "tester") || !key_authorized(pubkey)) return SSH_AUTH_DENIED;
    if (signature_state == SSH_PUBLICKEY_STATE_NONE) return SSH_AUTH_SUCCESS; /* libssh answers PK_OK */
    if (signature_state != SSH_PUBLICKEY_STATE_VALID) return SSH_AUTH_DENIED;
    c->authenticated = 1;
    return SSH_AUTH_SUCCESS;
}
static int exec_request(ssh_session s, ssh_channel ch, const char *command, void *data)
{
    (void)s; (void)ch; (void)command;
    struct channel *c = data;
    c->exec_pending = 1;
    return SSH_OK;
}
static int discard(ssh_session s, ssh_channel ch, void *buf, uint32_t len,
                   int is_stderr, void *data)
{
    (void)s; (void)ch; (void)buf; (void)is_stderr; (void)data;
    return (int)len;
}
static void channel_closed(ssh_session s, ssh_channel ch, void *data)
{
    (void)s; (void)data;
    ssh_channel_close(ch);
}
static ssh_channel open_session(ssh_session s, void *data)
{
    struct connection *conn = data;
    if (!conn->authenticated) return NULL;
    struct channel *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->handle = ssh_channel_new(s);
    if (!c->handle) { free(c); return NULL; }
    c->callbacks.userdata = c;
    c->callbacks.channel_exec_request_function = exec_request;
    c->callbacks.channel_data_function = discard;
    c->callbacks.channel_close_function = channel_closed;
    ssh_callbacks_init(&c->callbacks);
    ssh_set_channel_callbacks(c->handle, &c->callbacks);
    c->next = conn->channels;
    conn->channels = c;
    return c->handle;
}
static void *serve(void *arg)
{
    ssh_session s = arg;
    struct connection conn = {0};
    struct ssh_server_callbacks_struct cb = {
        .userdata = &conn,
        .auth_password_function = password,
        .auth_pubkey_function = auth_pubkey,
        .channel_open_request_session_function = open_session,
    };
    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(s, &cb);
    ssh_set_auth_methods(s, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_PUBLICKEY);
    ssh_event event = ssh_event_new();
    if (event && ssh_handle_key_exchange(s) == SSH_OK &&
        ssh_event_add_session(event, s) == SSH_OK) {
        while (ssh_is_connected(s)) {
            if (ssh_event_dopoll(event, 1000) == SSH_ERROR) break;
            for (struct channel *c = conn.channels; c; c = c->next) {
                if (c->exec_pending) {
                    /* Run after libssh has sent the exec success reply. */
                    c->exec_pending = 0;
                    ssh_channel_request_send_exit_status(c->handle, 0);
                    ssh_channel_send_eof(c->handle);
                    ssh_channel_close(c->handle);
                }
            }
        }
        ssh_event_remove_session(event, s);
    }
    if (ssh_get_error_code(s)) fprintf(stderr, "%s\n", ssh_get_error(s));
    if (event) ssh_event_free(event);
    while (conn.channels) {
        struct channel *c = conn.channels;
        conn.channels = c->next;
        ssh_channel_free(c->handle);
        free(c);
    }
    ssh_disconnect(s);
    ssh_free(s);
    return NULL;
}
int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    if (ssh_init() != SSH_OK) return 1;
    ssh_key key = NULL;
    ssh_bind bind = ssh_bind_new();
    int port = 22, config = 0;
    /* Generate a fresh Ed25519 host key once per container start. */
    if (!bind || ssh_pki_generate_key(SSH_KEYTYPE_ED25519, NULL, &key) != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &config) != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0") != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT, &port) != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_IMPORT_KEY, key) != SSH_OK ||
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, "/etc/psm/ssh_host_rsa_key") != SSH_OK ||
        ssh_bind_listen(bind) != SSH_OK) {
        fprintf(stderr, "Failed to initialize libssh server\n");
        return 1;
    }
    for (;;) {
        ssh_session s = ssh_new();
        if (!s) return 1;
        if (ssh_bind_accept(bind, s) == SSH_OK) {
            pthread_t thread;
            if (pthread_create(&thread, NULL, serve, s) == 0) {
                pthread_detach(thread);
                continue;
            }
        }
        ssh_free(s);
    }
}
