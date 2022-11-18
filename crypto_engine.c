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
    //printf("GAGAN : Test that custom engine invoked\n");
    //Use this to send the secret to the iokernel
    printf("GAGAN : Testing is_enc value %d\n", is_enc);
    /*if(is_enc) {*/
        //printf("GAGAN : Exporting secrets to iokernel only for encryption\n");
    printf("GAGAN : Epoch when exporting secrets is %lu\n", epoch);
    printf("GAGAN : Hash digest size when exporting secrets is %d\n", hash->digest_size);
    printf("GAGAN : Hash block size when exporting secrets is %d\n", hash->block_size);
    printf("GAGAN : AEAD algorithm when exporting secrets is %s\n", aead->name);
    printf("GAGAN : AEAD algorithm name size when exporting secrets is %d\n", strlen(aead->name));
    char hexbuf[PTLS_MAX_DIGEST_SIZE * 2 + 1];
    ptls_hexdump(hexbuf, secret, hash->digest_size);
    char *embed_name = "128";
    char *embed_epoch = "0";
    char *embed_enc = "e";
    if(strcmp(aead->name, "AES256-GCM") == 0) {
        embed_name = "256";
    }

    if(epoch == 1) {
       embed_epoch = "1"; 
    } else if(epoch == 2) {
        embed_epoch = "2";
    } else if(epoch == 3) {
        embed_epoch = "3";
    }

    if(is_enc == 0) {
        embed_enc = "d";
    }

    //printf("GAGAN : Secret when exporting secrets is %s\n", hexbuf);
    //printf("GAGAN : Embedding name and length %s - %lu\n", embed_name, strlen(embed_name));
    //printf("GAGAN : Embedding epoch and length %s - %lu\n", embed_epoch, strlen(embed_epoch));
    memcpy((char*)secret+(hash->digest_size), embed_name, strlen(embed_name));
    memcpy((char*)secret+(hash->digest_size)+strlen(embed_name), embed_epoch, strlen(embed_epoch));
    memcpy((char*)secret+(hash->digest_size)+strlen(embed_name)+strlen(embed_epoch), embed_enc, strlen(embed_enc));
    //printf("GAGAN : Total length being exported is %lu\n", hash->digest_size+strlen(embed_name)+strlen(embed_epoch));
    send_to_iokernel(secret, hash->digest_size+strlen(embed_name)+strlen(embed_epoch)+strlen(embed_enc));
    /*}*/
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
    //printf("GAGAN : Encryption function packet details\n");
    //printf("GAGAN : Datagram length in encryption function %lu\n", datagram.len);
    //Ideally, first byte at should be 0 since we do not coalesce multipe quic packets into a udp datagram
    //printf("GAGAN : First byte at %lu\n", first_byte_at);
    //payload from will indicate the point at which the quic payload starts
    //printf("GAGAN : Payload from %lu\n", payload_from);
    //printf("GAGAN : Packet number %lu\n", packet_number);
    //printf("GAGAN : Dumping encrypted packet content to test things out\n"); //use quicly_hexdump
    //printf("GAGAN : Printing packet epoch details %d\n", get_epoch(*(datagram.base+first_byte_at)));
    //printf("GAGAN : Checking if packets are coalesced %d\n", coalesced);
    uint8_t epoch = get_epoch(*(datagram.base+first_byte_at));
    /*ptls_aead_supplementary_encryption_t supp = {.ctx = header_protect_ctx,*/
                                                 /*.input = datagram.base + payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE}; //don't understand the "+ QUICLY_MAX_PN_SIZE"*/

    //GAGAN
    /*ptls_aead_encrypt_s(packet_protect_ctx, datagram.base + payload_from, datagram.base + payload_from,*/
                        /*datagram.len - payload_from - packet_protect_ctx->algo->tag_size, packet_number,*/
                        /*datagram.base + first_byte_at, payload_from - first_byte_at, &supp);*/
    //Populate cipher meta subarray with relevant info needed for encryption and extracting chunks of data in iokernel

    //Create cipher meta here to be able to encrypt packet later
    unsigned long packet_len = datagram.len - first_byte_at;
    unsigned long header_len = payload_from - first_byte_at;
    unsigned long body_len = datagram.len - payload_from - packet_protect_ctx->algo->tag_size; 
    //printf("GAGAN : Packet, header, and body len are %lu, %lu, %lu\n", packet_len, header_len, body_len);
    /*printf("\n\n\n\n");*/
    struct cipher_meta *cm = (struct cipher_meta *)malloc(1*sizeof(struct cipher_meta));
    //add check to ensure allocation doesn't fail
    cm->aead_index = 0;
    cm->header_cipher_index = packet_len; //using this to temporarily store the length of the datagram
    cm->packet_num = packet_number;
    cm->header_len = header_len;
    cm->body_len = body_len;
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

size_t quicly_decode_decrypted_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *datagram, size_t datagram_size,
                            size_t *off)
{
    //leave processing for VN and retry packets as is
    const uint8_t *src = datagram, *src_end = datagram + datagram_size;

    assert(*off <= datagram_size);

    packet->octets = ptls_iovec_init(src + *off, datagram_size - *off);
    if (packet->octets.len < 2)
        goto Error;
    packet->datagram_size = *off == 0 ? datagram_size : 0;
    packet->token = ptls_iovec_init(NULL, 0);
    packet->decrypted.pn = UINT64_MAX;

    /* move the cursor to the second byte */
    src += *off + 1;

    if (QUICLY_PACKET_IS_LONG_HEADER(packet->octets.base[0])) {
        /* long header */
        uint64_t rest_length;
        if (src_end - src < 5)
            goto Error;
        packet->version = quicly_decode32(&src);
        packet->cid.dest.encrypted.len = *src++;
        if (src_end - src < packet->cid.dest.encrypted.len + 1)
            goto Error;
        packet->cid.dest.encrypted.base = (uint8_t *)src;
        src += packet->cid.dest.encrypted.len;
        packet->cid.src.len = *src++;
        if (src_end - src < packet->cid.src.len)
            goto Error;
        packet->cid.src.base = (uint8_t *)src;
        src += packet->cid.src.len;
        switch (packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) {
        case QUICLY_PACKET_TYPE_INITIAL:
        case QUICLY_PACKET_TYPE_0RTT:
            if (ctx->cid_encryptor == NULL || packet->cid.dest.encrypted.len == 0 ||
                ctx->cid_encryptor->decrypt_cid(ctx->cid_encryptor, &packet->cid.dest.plaintext, packet->cid.dest.encrypted.base,
                                                packet->cid.dest.encrypted.len) == SIZE_MAX)
                packet->cid.dest.plaintext = quicly_cid_plaintext_invalid;
            packet->cid.dest.might_be_client_generated = 1;
            break;
        default:
            if (ctx->cid_encryptor != NULL) {
                if (packet->cid.dest.encrypted.len == 0)
                    goto Error;
                if (ctx->cid_encryptor->decrypt_cid(ctx->cid_encryptor, &packet->cid.dest.plaintext,
                                                    packet->cid.dest.encrypted.base, packet->cid.dest.encrypted.len) == SIZE_MAX)
                    goto Error;
            } else {
                packet->cid.dest.plaintext = quicly_cid_plaintext_invalid;
            }
            packet->cid.dest.might_be_client_generated = 0;
            break;
        }
        switch (packet->version) {
        case QUICLY_PROTOCOL_VERSION_1:
        case QUICLY_PROTOCOL_VERSION_DRAFT29:
        case QUICLY_PROTOCOL_VERSION_DRAFT27:
            /* these are the recognized versions, and they share the same packet header format */
            if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_RETRY) {
                /* retry */
                if (src_end - src <= PTLS_AESGCM_TAG_SIZE)
                    goto Error;
                packet->token = ptls_iovec_init(src, src_end - src - PTLS_AESGCM_TAG_SIZE);
                src += packet->token.len;
                packet->encrypted_off = src - packet->octets.base;
            } else {
                /* coalescible long header packet */
                if ((packet->octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) == QUICLY_PACKET_TYPE_INITIAL) {
                    /* initial has a token */
                    uint64_t token_len;
                    if ((token_len = quicly_decodev(&src, src_end)) == UINT64_MAX)
                        goto Error;
                    if (src_end - src < token_len)
                        goto Error;
                    packet->token = ptls_iovec_init(src, token_len);
                    src += token_len;
                }
                if ((rest_length = quicly_decodev(&src, src_end)) == UINT64_MAX)
                    goto Error;
                if (rest_length < 1)
                    goto Error;
                if (src_end - src < rest_length)
                    goto Error;
                packet->encrypted_off = src - packet->octets.base;
                packet->octets.len = packet->encrypted_off + rest_length;

                //decode the encoded packet number
                packet->decrypted.pn = quicly_decode16(&(packet->octets.base+packet->encrypted_off));
                size_t pnlen = (packet->octets.base[0] & 0x3) + 1;
                packet->encrypted_off = packet->encrypted_off+pnlen;
            }
            break;
        default:
            /* VN packet or packets of unknown version cannot be parsed. `encrypted_off` is set to the first byte after SCID. */
            packet->encrypted_off = src - packet->octets.base;
        }
        packet->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_NOT_STATELESS_RESET;
    } else {
        /* short header */
        if (ctx->cid_encryptor != NULL) {
            if (src_end - src < QUICLY_MAX_CID_LEN_V1)
                goto Error;
            size_t local_cidl = ctx->cid_encryptor->decrypt_cid(ctx->cid_encryptor, &packet->cid.dest.plaintext, src, 0);
            if (local_cidl == SIZE_MAX)
                goto Error;
            packet->cid.dest.encrypted = ptls_iovec_init(src, local_cidl);
            src += local_cidl;
        } else {
            packet->cid.dest.encrypted = ptls_iovec_init(NULL, 0);
            packet->cid.dest.plaintext = quicly_cid_plaintext_invalid;
        }
        packet->cid.dest.might_be_client_generated = 0;
        packet->cid.src = ptls_iovec_init(NULL, 0);
        packet->version = 0;
        packet->encrypted_off = src - packet->octets.base;
        packet->_is_stateless_reset_cached = QUICLY__DECODED_PACKET_CACHED_MAYBE_STATELESS_RESET;

        //decode the encoded packet number
        packet->decrypted.pn = quicly_decode16(&(packet->octets.base+packet->encrypted_off));
        size_t pnlen = (packet->octets.base[0] & 0x3) + 1;
        packet->encrypted_off = packet->encrypted_off+pnlen;
    }

    *off += packet->octets.len;
    return packet->octets.len;

Error:
    return SIZE_MAX;
}
