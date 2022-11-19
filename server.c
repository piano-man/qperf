#include "server.h"
#include "server_stream.h"
#include "common.h"
#include "crypto_engine.h"

#include <stdio.h>
#include <ev.h>
#include <quicly.h>
#include <quicly/defaults.h>
#include <unistd.h>
#include <float.h>
#include <inttypes.h>
#include <stdbool.h>

#include <quicly/streambuf.h>

#include <picotls/openssl.h>
#include <picotls/../../t/util.h>

#include <runtime/poll.h>
#include <runtime/tcp.h>
#include <runtime/udp.h>

static quicly_conn_t **conns;
static quicly_context_t server_ctx;
static size_t num_conns = 0;
static ev_timer server_timeout;
static quicly_cid_plaintext_t next_cid;

static udpconn_t *c = NULL;


static inline quicly_conn_t *find_conn(struct sockaddr *sa, socklen_t salen, quicly_decoded_packet_t *packet)
{
    for(size_t i = 0; i < num_conns; ++i) {
        if(quicly_is_destination(conns[i], NULL, sa, packet)) {
            return conns[i];
        }
    }
    return NULL;
}

static void append_conn(quicly_conn_t *conn)
{
    ++num_conns;
    conns = realloc(conns, sizeof(quicly_conn_t*) * num_conns);
    assert(conns != NULL);
    conns[num_conns - 1] = conn;

    *quicly_get_data(conn) = calloc(1, sizeof(int64_t));
}

static size_t remove_conn(size_t i)
{
    free(*quicly_get_data(conns[i]));
    quicly_free(conns[i]);
    memmove(conns + i, conns + i + 1, (num_conns - i - 1) * sizeof(quicly_conn_t*));
    --num_conns;
    return i - 1;
}

static void server_timeout_cb(EV_P_ ev_timer *w, int revents);

static int visits = 0;
void server_send_pending()
{
    int64_t next_timeout = INT64_MAX;
    for(size_t i = 0; i < num_conns; ++i) {
        if (!send_pending(&server_ctx, c, conns[i])) {
            i = remove_conn(i);
        } else {
            next_timeout = min_int64(quicly_get_first_timeout(conns[i]), next_timeout);
        }
    }

    /*visits++;

      if (visits >= 1000){
      printf("still trying to send\n");
      visits = 0;
      }*/


    int64_t now = server_ctx.now->cb(server_ctx.now);
    int64_t timeout = clamp_int64(next_timeout - now, 1, 200);
    server_timeout.repeat = timeout / 1000.;
    ev_timer_again(EV_DEFAULT, &server_timeout);
}

static void server_timeout_cb(EV_P_ ev_timer *w, int revents)
{
    server_send_pending();
}

static inline void server_handle_packet(quicly_decoded_packet_t *packet, struct sockaddr *sa, socklen_t salen)
{
    quicly_conn_t *conn = find_conn(sa, salen, packet);
    if(conn == NULL) {
        // new conn
        int ret = quicly_accept(&conn, &server_ctx, 0, sa, packet, NULL, &next_cid, NULL);
        /*send_to_iokernel(conn->application->cipher->egress.secret, sizeof(conn->application->cipher->egress.secret));*/
        if(ret != 0) {
            printf("quicly_accept failed with code %i\n", ret);
            return;
        }
        ++next_cid.master_id;
        printf("got new connection\n");
        append_conn(conn);
    } else {
        int ret = quicly_receive(conn, NULL, sa, packet);
        if(ret != 0 && ret != QUICLY_ERROR_PACKET_IGNORED) {
            fprintf(stderr, "quicly_receive returned %i\n", ret);
            exit(1);
        }
    }
}

static void server_read_cb(void *q)
{
    // retrieve data
    uint8_t buf[4096];
    struct netaddr raddr;
    quicly_decoded_packet_t packet;
    ssize_t bytes_received;
    struct sockaddr sa;
    struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
    socklen_t salen = sizeof(sa);

    while (true) {
        bool is_decrypted = true;
        ssize_t bytes_received = udp_read_from((udpconn_t *)q, buf, sizeof(buf), &raddr, &is_decrypted);
        if (bytes_received == 0) break;
        if(!is_decrypted) {
            for(ssize_t offset = 0; offset < bytes_received; ) {
                size_t packet_len = quicly_decode_decrypted_packet(&server_ctx, &packet, buf, bytes_received, &offset);
                if(packet_len == SIZE_MAX) {
                    printf("this??!\n");
                    break;
                }
                sin->sin_family = AF_INET;
                sin->sin_addr.s_addr = htonl(raddr.ip);
                sin->sin_port = htons(raddr.port);

                server_handle_packet(&packet, &sa, salen);
            }
        } else {
            //we get a decrypted packet from the iokernel
        }
    }

    //server_send_pending();
    for(size_t i = 0; i < num_conns; ++i) {
        if (!send_pending(&server_ctx, c, conns[i])) {
            i = remove_conn(i);
        }
    }
}

static void server_on_conn_close(quicly_closed_by_remote_t *self, quicly_conn_t *conn, int err,
        uint64_t frame_type, const char *reason, size_t reason_len)
{
    if (QUICLY_ERROR_IS_QUIC_TRANSPORT(err)) {
        fprintf(stderr, "transport close:code=0x%" PRIx16 ";frame=%" PRIu64 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err),
                frame_type, (int)reason_len, reason);
    } else if (QUICLY_ERROR_IS_QUIC_APPLICATION(err)) {
        fprintf(stderr, "application close:code=0x%" PRIx16 ";reason=%.*s\n", QUICLY_ERROR_GET_ERROR_CODE(err), (int)reason_len,
                reason);
    } else if (err == QUICLY_ERROR_RECEIVED_STATELESS_RESET) {
        fprintf(stderr, "stateless reset\n");
    } else {
        fprintf(stderr, "unexpected close:code=%d\n", err);
    }
}

static quicly_stream_open_t stream_open = {&server_on_stream_open};
static quicly_closed_by_remote_t closed_by_remote = {&server_on_conn_close};

int run_server(const char *port, bool gso, const char *logfile, const char *cc, int iw, const char *cert, const char *key)
{
    setup_session_cache(get_tlsctx());
    quicly_amend_ptls_context(get_tlsctx());

    server_ctx = quicly_spec_context;
    server_ctx.tls = get_tlsctx();
    server_ctx.stream_open = &stream_open;
    server_ctx.closed_by_remote = &closed_by_remote;
    server_ctx.transport_params.max_stream_data.uni = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_local = UINT32_MAX;
    server_ctx.transport_params.max_stream_data.bidi_remote = UINT32_MAX;
    server_ctx.initcwnd_packets = iw;
    //GAGAN: Registering new crypto engine
    server_ctx.initial_egress_max_udp_payload_size = 1458;
    server_ctx.transport_params.max_udp_payload_size = 1458;
    server_ctx.crypto_engine = &custom_crypto_engine;

    if(strcmp(cc, "reno") == 0) {
        server_ctx.init_cc = &quicly_cc_reno_init;
    } else if(strcmp(cc, "cubic") == 0) {
        server_ctx.init_cc = &quicly_cc_cubic_init;
    }

    if (gso) {
        enable_gso();
    }

    load_certificate_chain(server_ctx.tls, cert);
    load_private_key(server_ctx.tls, key);

    struct ev_loop *loop = EV_DEFAULT;


    // create shenango socket
    struct netaddr local_addr;
    local_addr.ip = 0;
    local_addr.port = atoi(port);
    //udpconn_t *c;
    int ret = udp_listen(local_addr, &c);
    if (ret) {
        printf("failed to listen on port %s\n", port);
        return 1;
    }

    udp_set_nonblocking(c, true);

    // create shenango event loop
    poll_trigger_t *t;
    ret = create_trigger(&t);
    if (ret) {
        printf("failed to create trigger\n");
        return 1;
    }
    poll_waiter_t *w;
    ret = create_waiter(&w);
    if (ret) {
        printf("failed to create waiter\n");
        return 1;
    }

    poll_arm_w_sock(w, udp_get_triggers(c), t, SEV_READ, &server_read_cb, c, c);

    if (logfile)
    {
        setup_log_event(server_ctx.tls, logfile);
    }

    printf("starting server with pid %" PRIu64 ", port %s, cc %s, iw %i\n", get_current_pid(), port, cc, iw);


    // add ev loop here for shenango and add some timeout mechanism
    //ev_init(&server_timeout, &server_timeout_cb);

    while (true) {
        poll_cb_once(w);
        ev_run(loop, EVRUN_NOWAIT);
        for(size_t i = 0; i < num_conns; ++i) {
            if (!send_pending(&server_ctx, c, conns[i])) {
                i = remove_conn(i);
                printf("removed conn\n");
            }
        }
    }

    return 0;
}

