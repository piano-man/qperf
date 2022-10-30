#include "crypto_engine.h"
#include "common.h"
#include <string.h>
#include <quicly/defaults.h>
#include <quicly/../quicly.h>
#include <runtime/poll.h>
#include <runtime/tcp.h>
#include <runtime/udp.h>
#include <runtime/net.h>
#include <assert.h>

static inline uint8_t get_epoch(uint8_t first_byte)
{
    if (!QUICLY_PACKET_IS_LONG_HEADER(first_byte))
        return QUICLY_EPOCH_1RTT;

    switch (first_byte & QUICLY_PACKET_TYPE_BITMASK) {
    case QUICLY_PACKET_TYPE_INITIAL:
        return QUICLY_EPOCH_INITIAL;
    case QUICLY_PACKET_TYPE_HANDSHAKE:
        return QUICLY_EPOCH_HANDSHAKE;
    case QUICLY_PACKET_TYPE_0RTT:
        return QUICLY_EPOCH_0RTT;
    default:
        assert(!"FIXME");
    }
}
static int default_setup_cipher(quicly_crypto_engine_t *engine, quicly_conn_t *conn, size_t epoch, int is_enc,
                                ptls_cipher_context_t **hp_ctx, ptls_aead_context_t **aead_ctx, ptls_aead_algorithm_t *aead,
                                ptls_hash_algorithm_t *hash, const void *secret)
{
    printf("GAGAN: Test that custom engine invoked\n");
    //Use this to send the secret to the iokernel
    printf("GAGAN: Testing is_enc value %d\n", is_enc);
    if(is_enc) {
        printf("GAGAN: Exporting secrets to iokernel only for encryption\n");
        printf("GAGAN: Epoch when exporting secrets is %lu\n", epoch);
        printf("GAGAN: Hash digest size when exporting secrets is %d\n", hash->digest_size);
        printf("GAGAN: Hash block size when exporting secrets is %d\n", hash->block_size);
        printf("GAGAN: AEAD algorithm when exporting secrets is %s\n", aead->name);
        printf("GAGAN: AEAD algorithm name size when exporting secrets is %d\n", strlen(aead->name));
        printf("GAGAN: Secret when exporting secrets is %s\n", (char *)secret);
        memcpy(secret+(hash->digest_size), aead->name, strlen(aead->name));
        send_to_iokernel(secret, hash->digest_size+strlen(aead->name));
    }
    uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
    int ret;

    if (hp_ctx != NULL)
        *hp_ctx = NULL;
    *aead_ctx = NULL;

    /* generate new header protection key */
    if (hp_ctx != NULL) {
        if ((ret = ptls_hkdf_expand_label(hash, hpkey, aead->ctr_cipher->key_size, ptls_iovec_init(secret, hash->digest_size),
                                          "quic hp", ptls_iovec_init(NULL, 0), NULL)) != 0)
            goto Exit;
        if ((*hp_ctx = ptls_cipher_new(aead->ctr_cipher, is_enc, hpkey)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
    }

    /* generate new AEAD context */
    if ((*aead_ctx = ptls_aead_new(aead, hash, is_enc, secret, QUICLY_AEAD_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    ret = 0;
Exit:
    if (ret != 0) {
        if (*aead_ctx != NULL) {
            ptls_aead_free(*aead_ctx);
            *aead_ctx = NULL;
        }
        if (hp_ctx != NULL && *hp_ctx != NULL) {
            ptls_cipher_free(*hp_ctx);
            *hp_ctx = NULL;
        }
    }
    ptls_clear_memory(hpkey, sizeof(hpkey));
    return ret;
}

static void default_finalize_send_packet(quicly_crypto_engine_t *engine, quicly_conn_t *conn,
                                         ptls_cipher_context_t *header_protect_ctx, ptls_aead_context_t *packet_protect_ctx,
                                         ptls_iovec_t datagram, size_t first_byte_at, size_t payload_from, uint64_t packet_number,
                                         int coalesced)
{
    printf("GAGAN: Encryption function packet details\n");
    printf("GAGAN: Datagram length in encryption function %lu\n", datagram.len);
    //Ideally, first byte at should be 0 since we do not coalesce multipe quic packets into a udp datagram
    printf("GAGAN: First byte at %lu\n", first_byte_at);
    //payload from will indicate the point at which the quic payload starts
    printf("GAGAN: Payload from %lu\n", payload_from);
    printf("GAGAN: Packet number %lu\n", packet_number);
    printf("GAGAN: Dumping encrypted packet content to test things out\n"); //use quicly_hexdump
    printf("GAGAN: Printing packet epoch details %d\n", get_epoch(datagram.base+first_byte_at));
    uint8_t epoch = get_epoch(datagram.base+first_byte_at);
    printf("\n\n\n\n");
    ptls_aead_supplementary_encryption_t supp = {.ctx = header_protect_ctx,
                                                 .input = datagram.base + payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE};

    //GAGAN
    /*ptls_aead_encrypt_s(packet_protect_ctx, datagram.base + payload_from, datagram.base + payload_from,*/
                        /*datagram.len - payload_from - packet_protect_ctx->algo->tag_size, packet_number,*/
                        /*datagram.base + first_byte_at, payload_from - first_byte_at, &supp);*/
    //Populate cipher meta subarray with relevant info needed for encryption and extracting chunks of data in iokernel

    //Create cipher meta here to be able to encrypt packet later
    unsigned long header_len = payload_from - first_byte_at;
    //GAGAN: Check how to determine body len accurately
    //If packets are being padded to MTU size, can exact computation of this be avoided?
    unsigned long body_len = datagram.len - payload_from; //Do we need to subtract tag_size?
    struct cipher_meta *cm = (struct cipher_meta *)malloc(1*sizeof(struct cipher_meta));
    //add check to ensure allocation doesn't fail
    cm->aead_index = 0;
    cm->header_cipher_index = datagram.len; //using this to temporarily store the length of the datagram
    cm->packet_num = packet_number;
    cm->header_len = first_byte_at; //should be 0
    cm->body_len = payload_from;
    //datagram.len-payload_from should give the body_len
    //payload_from-first_byte_at should give the header_len
    cm->header_form = epoch;//this will be needed if we move header encryption to the iokernel
    cipher_meta_vec[cm_count++] = cm;

    //GAGAN: This looks to be header encryption
    //Exported this to the iokernel as well
    //Could explore the tradeoff between doing this here and in the iokernel
    /*datagram.base[first_byte_at] ^= supp.output[0] & (QUICLY_PACKET_IS_LONG_HEADER(datagram.base[first_byte_at]) ? 0xf : 0x1f);*/
    /*for (size_t i = 0; i != QUICLY_SEND_PN_SIZE; ++i)*/
        /*datagram.base[payload_from + i - QUICLY_SEND_PN_SIZE] ^= supp.output[i + 1];*/
}

quicly_crypto_engine_t custom_crypto_engine = {default_setup_cipher, default_finalize_send_packet};
