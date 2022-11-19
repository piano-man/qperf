#include <quicly.h>

extern quicly_crypto_engine_t custom_crypto_engine; 
size_t quicly_decode_decrypted_packet(quicly_context_t *ctx, quicly_decoded_packet_t *packet, const uint8_t *datagram, size_t datagram_size, size_t *off);
