#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#include "encrypt.h"
#include "utils.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

static uint8_t *enc_table;
static uint8_t *dec_table;
static uint8_t enc_key[EVP_MAX_KEY_LENGTH];
static int enc_key_len;
static int enc_iv_len;

#ifdef DEBUG
static dump(char *tag, char *text)
{
    int i, len;
    len = strlen(text);
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
    {
        printf("0x%02x ", (uint8_t)text[i]);
    }
    printf("\n");
}
#endif

static const char* supported_ciphers[CIPHER_NUM] =
{
    "table",
    "rc4",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb"
};

static int random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a)
{
    uint8_t x = *((uint8_t *) _x);
    uint8_t y = *((uint8_t*) _y);
    return (a % (x + i) - a % (y + i));
}

static void merge(uint8_t *left, int llength, uint8_t *right,
                  int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *) malloc(llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *) malloc(rlength * sizeof(uint8_t));

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, llength * sizeof(uint8_t));
    memcpy(rtmp, right, rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0)
    {
        if (random_compare(ll, rr, salt, key) <= 0)
        {
            *result = *ll;
            ++ll;
            --llength;
        }
        else
        {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0)
        while (llength > 0)
        {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    else
        while (rlength > 0)
        {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }

    free(ltmp);
    free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
                       uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1)
        return;

    middle = length / 2;

    llength = length - middle;

    left = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

int enc_get_iv_len()
{
    return enc_iv_len;
}

void enc_table_init(const char *pass)
{
    uint32_t i;
    uint32_t salt;
    uint64_t key = 0;
    uint8_t *digest;

    enc_table = malloc(256);
    dec_table = malloc(256);

    digest = MD5((const uint8_t *)pass, strlen(pass), NULL);

    for (i = 0; i < 8; i++)
    {
        key += OFFSET_ROL(digest, i);
    }

    for(i = 0; i < 256; ++i)
    {
        enc_table[i] = i;
    }
    for(i = 1; i < 1024; ++i)
    {
        salt = i;
        merge_sort(enc_table, 256, salt, key);
    }
    for(i = 0; i < 256; ++i)
    {
        // gen decrypt table from encrypt table
        dec_table[enc_table[i]] = i;
    }
}

char* ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method)
{
    if (method > TABLE)
    {
        const EVP_CIPHER *cipher = EVP_get_cipherbyname(supported_ciphers[method]);
        if (cipher == NULL)
        {
            LOGE("Cipher %s not found in OpenSSL library", supported_ciphers[method]);
            FATAL("Cannot initialize cipher");
        }
        EVP_CIPHER_CTX evp;
        EVP_CIPHER_CTX_init(&evp);
        if (!EVP_CipherInit_ex&(evp, cipher, NULL, NULL, NULL, 1))
        {
            LOGE("Cannot initialize cipher %s", supported_ciphers[method]);
            exit(EXIT_FAILURE);
        }
        if (!EVP_CIPHER_CTX_set_key_length(&evp, enc_key_len))
        {
            EVP_CIPHER_CTX_cleanup(&evp);
            LOGE("Invalid key length: %d", enc_key_len);
            exit(EXIT_FAILURE);
        }
        if (method > RC4)
        {
            EVP_CIPHER_CTX_set_padding(&evp, 1);
        }

        int c_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        char *ciphertext = malloc(max(iv_len + c_len, buf_size));

        uint8_t iv[EVP_MAX_IV_LENGTH];
        iv_len = enc_iv_len;
        RAND_bytes(iv, iv_len);
        EVP_CipherInit_ex(&evp, NULL, NULL, enc_key, iv, 1);
        memcpy(ciphertext, iv, iv_len);

#ifdef DEBUG
        dump("IV", iv);
#endif

        err = EVP_EncryptUpdate(&evp, (uint8_t*)(ciphertext+iv_len),
                                &c_len, (const uint8_t *)plaintext, *len);

        if (!err)
        {
            free(ciphertext);
            free(plaintext);
            EVP_CIPHER_CTX_cleanup(&evp);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext);
        dump("CIPHER", ciphertext);
#endif

        *len = iv_len + c_len;
        free(plaintext);
        EVP_CIPHER_CTX_cleanup(&evp);

        return ciphertext;

    }
    else
    {
        char *begin = plaintext;
        while (plaintext < begin + *len)
        {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
    }
}

char* ss_encrypt(int buf_size, char *plaintext, ssize_t *len, struct enc_ctx *ctx)
{
    if (ctx != NULL)
    {
        int c_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        char *ciphertext = malloc(max(iv_len + c_len, buf_size));

        if (!ctx->init)
        {
            uint8_t iv[EVP_MAX_IV_LENGTH];
            iv_len = enc_iv_len;
            RAND_bytes(iv, iv_len);
            EVP_CipherInit_ex(&ctx->evp, NULL, NULL, enc_key, iv, 1);
            memcpy(ciphertext, iv, iv_len);
#ifdef DEBUG
            dump("IV", iv);
#endif
        }

        err = EVP_EncryptUpdate(&ctx->evp, (uint8_t*)(ciphertext+iv_len),
                                &c_len, (const uint8_t *)plaintext, *len);
        if (!err)
        {
            free(ciphertext);
            free(plaintext);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext);
        dump("CIPHER", ciphertext);
#endif

        *len = iv_len + c_len;
        free(plaintext);
        return ciphertext;
    }
    else
    {
        char *begin = plaintext;
        while (plaintext < begin + *len)
        {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
    }
}

char* ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method)
{
    if (method > TABLE)
    {

        const EVP_CIPHER *cipher = EVP_get_cipherbyname(supported_ciphers[method]);
        if (cipher == NULL)
        {
            LOGE("Cipher %s not found in OpenSSL library", supported_ciphers[method]);
            FATAL("Cannot initialize cipher");
        }
        EVP_CIPHER_CTX evp;
        EVP_CIPHER_CTX_init(&evp);
        if (!EVP_CipherInit_ex&(evp, cipher, NULL, NULL, NULL, 0))
        {
            LOGE("Cannot initialize cipher %s", supported_ciphers[method]);
            exit(EXIT_FAILURE);
        }
        if (!EVP_CIPHER_CTX_set_key_length(&evp, enc_key_len))
        {
            EVP_CIPHER_CTX_cleanup(&evp);
            LOGE("Invalid key length: %d", enc_key_len);
            exit(EXIT_FAILURE);
        }
        if (method > RC4)
        {
            EVP_CIPHER_CTX_set_padding(&evp, 1);
        }

        int p_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        char *plaintext = malloc(max(p_len, buf_size));

        uint8_t iv[EVP_MAX_IV_LENGTH];
        iv_len = enc_iv_len;
        memcpy(iv, ciphertext, iv_len);
        EVP_CipherInit_ex(&evp, NULL, NULL, enc_key, iv, 0);

#ifdef DEBUG
        dump("IV", iv);
#endif

        err = EVP_DecryptUpdate(&evp, (uint8_t*)plaintext, &p_len,
                                (const uint8_t*)(ciphertext + iv_len), *len - iv_len);
        if (!err)
        {
            free(ciphertext);
            free(plaintext);
            EVP_CIPHER_CTX_cleanup(&evp);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext);
        dump("CIPHER", ciphertext);
#endif

        *len = p_len;
        free(ciphertext);
        EVP_CIPHER_CTX_cleanup(&evp);
        return plaintext;
    }
    else
    {
        char *begin = ciphertext;
        while (ciphertext < begin + *len)
        {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
    }
}

char* ss_decrypt(int buf_size, char *ciphertext, ssize_t *len, struct enc_ctx *ctx)
{
    if (ctx != NULL)
    {
        int p_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        char *plaintext = malloc(max(p_len, buf_size));

        if (!ctx->init)
        {
            uint8_t iv[EVP_MAX_IV_LENGTH];
            iv_len = enc_iv_len;
            memcpy(iv, ciphertext, iv_len);
            EVP_CipherInit_ex(&ctx->evp, NULL, NULL, enc_key, iv, 0);
            ctx->init = 1;
#ifdef DEBUG
            dump("IV", iv);
#endif
        }

        err = EVP_DecryptUpdate(&ctx->evp, (uint8_t*)plaintext, &p_len,
                                (const uint8_t*)(ciphertext + iv_len), *len - iv_len);

        if (!err)
        {
            free(ciphertext);
            free(plaintext);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext);
        dump("CIPHER", ciphertext);
#endif

        *len = p_len;
        free(ciphertext);
        return plaintext;
    }
    else
    {
        char *begin = ciphertext;
        while (ciphertext < begin + *len)
        {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
    }
}

void enc_ctx_init(int method, struct enc_ctx *ctx, int enc)
{
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(supported_ciphers[method]);
    if (cipher == NULL)
    {
        LOGE("Cipher %s not found in OpenSSL library", supported_ciphers[method]);
        FATAL("Cannot initialize cipher");
    }
    memset(ctx, 0, sizeof(struct enc_ctx));

    EVP_CIPHER_CTX *evp = &ctx->evp;

    EVP_CIPHER_CTX_init(evp);
    if (!EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc))
    {
        LOGE("Cannot initialize cipher %s", supported_ciphers[method]);
        exit(EXIT_FAILURE);
    }
    if (!EVP_CIPHER_CTX_set_key_length(evp, enc_key_len))
    {
        EVP_CIPHER_CTX_cleanup(evp);
        LOGE("Invalid key length: %d", enc_key_len);
        exit(EXIT_FAILURE);
    }
    if (method > RC4)
    {
        EVP_CIPHER_CTX_set_padding(evp, 1);
    }
}

void enc_key_init(int method, const char *pass)
{
    OpenSSL_add_all_algorithms();

    uint8_t iv[EVP_MAX_IV_LENGTH];
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(supported_ciphers[method]);
    if (cipher == NULL)
    {
        LOGE("Cipher %s not found in OpenSSL library", supported_ciphers[method]);
        FATAL("Cannot initialize cipher");
        return;
    }

    enc_key_len = EVP_BytesToKey(cipher, EVP_md5(), NULL, (uint8_t *)pass,
                                 strlen(pass), 1, enc_key, iv);
    enc_iv_len = EVP_CIPHER_iv_length(cipher);
}

int enc_init(const char *pass, const char *method)
{
    int m = TABLE;
    if (method != NULL)
    {
        for (m = TABLE; m < CIPHER_NUM; m++)
        {
            if (strcmp(method, supported_ciphers[m]) == 0)
            {
                break;
            }
        }
        if (m >= CIPHER_NUM)
        {
            LOGE("Invalid cipher name: %s, use table instead", method);
            m = TABLE;
        }
    }
    if (m == TABLE)
    {
        enc_table_init(pass);
    }
    else
    {
        enc_key_init(m, pass);
    }
    return m;
}

