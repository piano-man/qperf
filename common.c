#include "common.h"

#include <sys/socket.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <memory.h>
#include <picotls/openssl.h>
#include <errno.h>
#include <runtime/udp.h>

//GAGAN: What's an acceptable packet number here?
struct cipher_meta *cipher_meta_vec[10000];
int cm_count = 0;

ptls_context_t *get_tlsctx()
{
    static ptls_context_t tlsctx = {.random_bytes = ptls_openssl_random_bytes,
                                    .get_time = &ptls_get_time,
                                    .key_exchanges = ptls_openssl_key_exchanges,
                                    .cipher_suites = ptls_openssl_cipher_suites,
                                    .require_dhe_on_psk = 1};
    return &tlsctx;
}


ssize_t sendmsg2(udpconn_t *sock, const struct msghdr* message, int flags) {
  ssize_t bytesSent = 0;
  for (size_t i = 0; i < message->msg_iovlen; i++) {
    ssize_t r;
//    printf("iovec len %ld \n ", message->msg_iov[i].iov_len);
    if (message->msg_name != NULL) {
      r = udp_write_to(sock, (void*) message->msg_iov[i].iov_base,
                        (size_t) message->msg_iov[i].iov_len,
			 (struct netaddr*) message->msg_name, cipher_meta_vec, cm_count);
      //reset cm_count to 0
      cm_count = 0;
    } else {
      r = udp_write(sock, (void*) message->msg_iov[i].iov_base,
                        (size_t) message->msg_iov[i].iov_len, NULL, 0);
    }
    if (r == -1 || r != message->msg_iov[i].iov_len) {
      // Some error happened.
      // TODO: Handle Error?
      printf("This acutally happened!\n");
      return -1;
    }
    bytesSent += r;
  }
  return bytesSent;
}

struct addrinfo *get_address(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;                    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM;                 /* Datagram socket */
    hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV | AI_PASSIVE;
    hints.ai_protocol = IPPROTO_UDP;

    if(getaddrinfo(host, port, &hints, &result) != 0) {
        return NULL;
    } else {
        return result;
    }
}


bool send_dgrams_default(udpconn_t *fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    for(size_t i = 0; i < num_dgrams; ++i) {
	struct sockaddr_in *sin = (struct sockaddr_in *)dest;
	struct netaddr daddr;
	daddr.ip = ntohl(sin->sin_addr.s_addr);
	daddr.port = ntohs(sin->sin_port);

        struct msghdr mess = {
            .msg_name = &daddr,
            .msg_namelen = sizeof(daddr),
            .msg_iov = &dgrams[i], .msg_iovlen = 1
        };

	/*char sip[IP_ADDR_STR_LEN];
	uint32_t addr = daddr.ip;
	snprintf(sip, IP_ADDR_STR_LEN, "%d.%d.%d.%d",
           ((addr >> 24) & 0xff),
           ((addr >> 16) & 0xff),
           ((addr >> 8) & 0xff),
           (addr & 0xff));
	printf("trying to send %s  %d\n", sip, daddr.port);*/

        ssize_t bytes_sent;
        //while ((bytes_sent = sendmsg2(fd, &mess, 0)) == -1);
        bytes_sent = sendmsg2(fd, &mess, 0);
	if (bytes_sent == -1) {
            perror("sendmsg failed");
            return false;
        }
    }

    return true;
}

bool send_dgrams_gso(udpconn_t *fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams)
{
    struct iovec vec = {
        .iov_base = (void *)dgrams[0].iov_base,
        .iov_len = dgrams[num_dgrams - 1].iov_base + dgrams[num_dgrams - 1].iov_len - dgrams[0].iov_base
    };

    printf("GAGAN: Printing out the individual iovec lengths\n");
    printf("GAGAN: iovec 0 length %lu\n", dgrams[0].iov_len);
    printf("GAGAN: iovec last length %lu\n", dgrams[num_dgrams - 1].iov_len);

    struct sockaddr_in *sin = (struct sockaddr_in *)dest;
    struct netaddr daddr;
    daddr.ip = ntohl(sin->sin_addr.s_addr);
    daddr.port = ntohs(sin->sin_port);

    struct msghdr mess = {
        .msg_name = &daddr,
        .msg_namelen = sizeof(daddr),
        .msg_iov = &vec,
        .msg_iovlen = 1
    };

    /*union {
        struct cmsghdr hdr;
        char buf[CMSG_SPACE(sizeof(uint16_t))];
    } cmsg;
    if (num_dgrams != 1) {
        cmsg.hdr.cmsg_level = SOL_UDP;
        cmsg.hdr.cmsg_type = 103;//UDP_SEGMENT;
        cmsg.hdr.cmsg_len = CMSG_LEN(sizeof(uint16_t));
        *(uint16_t *)CMSG_DATA(&cmsg.hdr) = dgrams[0].iov_len;
        mess.msg_control = &cmsg;
        mess.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(uint16_t));
    }*/

    mess.msg_control = NULL;
    mess.msg_controllen = 0;
    mess.msg_flags = 0;

    ssize_t bytes_sent;
    while ((bytes_sent = sendmsg2(fd, &mess, 0)) == -1);
    if (bytes_sent == -1) {
        perror("sendmsg failed");
        return false;
    }

    return true;
}


///bool (*send_dgrams)(udpconn_t *fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams) = send_dgrams_default;
bool (*send_dgrams)(udpconn_t *fd, struct sockaddr *dest, struct iovec *dgrams, size_t num_dgrams) = send_dgrams_gso;
void enable_gso()
{
//    send_dgrams = send_dgrams_gso;
}

bool send_pending(quicly_context_t *ctx, udpconn_t *fd, quicly_conn_t *conn)
{
    #define SEND_BATCH_SIZE 16

    quicly_address_t dest, src;
    struct iovec dgrams[SEND_BATCH_SIZE];
    uint8_t dgrams_buf[SEND_BATCH_SIZE * ctx->transport_params.max_udp_payload_size];
    size_t num_dgrams = SEND_BATCH_SIZE;

    while(true) {
        int quicly_res = quicly_send(conn, &dest, &src, dgrams, &num_dgrams, &dgrams_buf, sizeof(dgrams_buf));
        if(quicly_res != 0) {
            if(quicly_res != QUICLY_ERROR_FREE_CONNECTION) {
                printf("quicly_send failed with code %i\n", quicly_res);
            } else {
                printf("connection closed\n");
            }
            return false;
        } else if(num_dgrams == 0) {
            return true;
        }

        //GAGAN: Loop here and confirm if all the datagrams are of the same size
        for(int i = 0 ; i < num_dgrams ; i++) {
            printf("GAGAN: Size of datagram %lu is %lu\n", i, dgrams[i].iov_len);
        }

        if (!send_dgrams(fd, &dest.sa, dgrams, num_dgrams)) {
            return false;
        }
    };
}

void print_escaped(const char *src, size_t len)
{
    for(size_t i = 0; i < len; ++i) {
        switch (src[i]) {
        case '\n':
            putchar('\\');
            putchar('n');
            break;
        case '\r':
            putchar('\\');
            putchar('r');
            break;
        default:
            putchar(src[i]);
        }
    }
    putchar('\n');
    fflush(stdout);
}

