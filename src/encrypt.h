/*
 * encrypt.h - Define the enryptor's interface
 *
 * Copyright (C) 2013 - 2015, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#ifndef __MINGW32__
#include <sys/socket.h>
#else

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
typedef EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

#elif defined(USE_CRYPTO_POLARSSL)

#include <polarssl/cipher.h>
#include <polarssl/md.h>
typedef cipher_info_t cipher_kt_t;
typedef cipher_context_t cipher_evp_t;
typedef md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH POLARSSL_MAX_IV_LENGTH
#define MAX_MD_SIZE POLARSSL_MD_MAX_SIZE

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif

#endif

#ifdef USE_CRYPTO_APPLECC

#include <CommonCrypto/CommonCrypto.h>

#define kCCAlgorithmInvalid UINT32_MAX
#define kCCContextValid 0
#define kCCContextInvalid -1

typedef struct {
    CCCryptorRef cryptor;
    int valid;
    CCOperation encrypt;
    CCAlgorithm cipher;
    CCMode mode;
    CCPadding padding;
    uint8_t iv[MAX_IV_LENGTH];
    uint8_t key[MAX_KEY_LENGTH];
    size_t iv_len;
    size_t key_len;
} cipher_cc_t;

#endif

typedef struct {
    cipher_evp_t evp;
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t cc;
#endif
    uint8_t iv[MAX_IV_LENGTH];
} cipher_ctx_t;

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#define SODIUM_BLOCK_SIZE   64
#define CIPHER_NUM          18

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define BF_CFB              6
#define CAMELLIA_128_CFB    7
#define CAMELLIA_192_CFB    8
#define CAMELLIA_256_CFB    9
#define CAST5_CFB           10
#define DES_CFB             11
#define IDEA_CFB            12
#define RC2_CFB             13
#define SEED_CFB            14
#define SALSA20             15
#define CHACHA20            16
#define CHACHA20IETF        17

#define ONETIMEAUTH_FLAG 0x10
#define ADDRTYPE_MASK 0xF

#define ONETIMEAUTH_BYTES 10U
#define CLEN_BYTES 2U
#define AUTH_BYTES (ONETIMEAUTH_BYTES + CLEN_BYTES)

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

typedef struct buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *array;
} buffer_t;

typedef struct chunk {
    uint32_t idx;
    uint32_t len;
    uint32_t counter;
    buffer_t *buf;
} chunk_t;

typedef struct enc_ctx {
    uint8_t init;
    uint64_t counter;
    cipher_ctx_t evp;
} enc_ctx_t;

int ss_encrypt_all(buffer_t *plaintext, int method, int auth, size_t capacity);
int ss_decrypt_all(buffer_t *ciphertext, int method, int auth, size_t capacity);
int ss_encrypt(buffer_t *plaintext, enc_ctx_t *ctx, size_t capacity);
int ss_decrypt(buffer_t *ciphertext, enc_ctx_t *ctx, size_t capacity);

void enc_ctx_init(int method, enc_ctx_t *ctx, int enc);
int enc_init(const char *pass, const char *method);
int enc_get_iv_len(void);
void cipher_context_release(cipher_ctx_t *evp);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);

int ss_onetimeauth(buffer_t *buf, uint8_t *iv, size_t capacity);
int ss_onetimeauth_verify(buffer_t *buf, uint8_t *iv);

int ss_check_hash(buffer_t *buf, chunk_t *chunk, enc_ctx_t *ctx, size_t capacity);
int ss_gen_hash(buffer_t *buf, uint32_t *counter, enc_ctx_t *ctx, size_t capacity);

int balloc(buffer_t *ptr, size_t capacity);
int brealloc(buffer_t *ptr, size_t len, size_t capacity);
void bfree(buffer_t *ptr);

#endif // _ENCRYPT_H
