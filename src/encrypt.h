#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include "config.h"

#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/evp.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define BLOCK_SIZE 32

#define CIPHER_NUM          14
#define NONE                -1
#define TABLE               0
#define RC4                 1
#define AES_128_CFB         2
#define AES_192_CFB         3
#define AES_256_CFB         4
#define BF_CFB              5
#define CAMELLIA_128_CFB    6
#define CAMELLIA_192_CFB    7
#define CAMELLIA_256_CFB    8
#define CAST5_CFB           9
#define DES_CFB             10
#define IDEA_CFB            11
#define RC2_CFB             12
#define SEED_CFB            13

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

struct enc_ctx
{
    uint8_t init;
    EVP_CIPHER_CTX evp;
};

char* ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method);
char* ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method);
char* ss_encrypt(int buf_size, char *plaintext, ssize_t *len, struct enc_ctx *ctx);
char* ss_decrypt(int buf_size, char *ciphertext, ssize_t *len, struct enc_ctx *ctx);
void enc_ctx_init(int method, struct enc_ctx *ctx, int enc);
int enc_init(const char *pass, const char *method);
int enc_get_iv_len(void);

#endif // _ENCRYPT_H
