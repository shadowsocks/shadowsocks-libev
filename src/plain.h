#ifndef _PLAIN_H
#define _PLAIN_H

#include "crypto.h"

int plain_stream_do_all(buffer_t *, cipher_t *, size_t);
int plain_stream_do(buffer_t *, cipher_ctx_t *, size_t);

void plain_stream_ctx_init(cipher_t *, cipher_ctx_t *, int);
void plain_stream_ctx_release(cipher_ctx_t *);

#endif // _PLAIN_H
