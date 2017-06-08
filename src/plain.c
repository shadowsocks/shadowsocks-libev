#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plain.h"

int
plain_stream_do_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
    (void)plaintext; (void)cipher; (void)capacity;

    return CRYPTO_OK;
}

int
plain_stream_do(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    (void)ciphertext; (void)cipher_ctx; (void)capacity;
    
    return CRYPTO_OK;
}

void
plain_stream_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    (void)cipher; (void)cipher_ctx; (void)enc;
}

void
plain_stream_ctx_release(cipher_ctx_t *cipher_ctx)
{
    (void)cipher_ctx;
}
