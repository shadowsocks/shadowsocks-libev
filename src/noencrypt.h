#ifndef _NOENCRYPT_H
#define _NOENCRYPT_H

#include "noencrypt.h"

int none_stream_all(buffer_t *, cipher_t *, size_t);
int none_stream(buffer_t *, cipher_ctx_t *, size_t);
void none_stream_ctx_init(cipher_t *, cipher_ctx_t *, int);
void none_stream_ctx_release(cipher_ctx_t *);

#endif //_NOENCRYPT_H