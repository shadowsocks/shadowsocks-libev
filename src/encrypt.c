#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <openssl/md5.h>

#include "encrypt.h"
#include "utils.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

static uint8_t *enc_table;
static uint8_t *dec_table;
static char *enc_pass;

#ifdef DEBUG
static dump(char *tag, char *text) {
    int i, len;
    len = strlen(text);
    printf("%s: ", tag);
    for (i = 0; i < len; i++) {
        printf("0x%02x ", (uint8_t)text[i]);
    }
    printf("\n");
}
#endif

static const char* supported_ciphers[8] = {
    "table",
    "rc4",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "cast5-cfb",
    "des-cfb"
};

static int random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a) {
    uint8_t x = *((uint8_t *) _x);
    uint8_t y = *((uint8_t*) _y);
    return (a % (x + i) - a % (y + i));
}

static void merge(uint8_t *left, int llength, uint8_t *right,
        int rlength, uint32_t salt, uint64_t key) {
	uint8_t *ltmp = (uint8_t *) malloc(llength * sizeof(uint8_t));
	uint8_t *rtmp = (uint8_t *) malloc(rlength * sizeof(uint8_t));

	uint8_t *ll = ltmp;
	uint8_t *rr = rtmp;

	uint8_t *result = left;

	memcpy(ltmp, left, llength * sizeof(uint8_t));
	memcpy(rtmp, right, rlength * sizeof(uint8_t));

	while (llength > 0 && rlength > 0) {
		if (random_compare(ll, rr, salt, key) <= 0) {
			*result = *ll;
			++ll;
			--llength;
		} else {
			*result = *rr;
			++rr;
			--rlength;
		}
		++result;
	}

	if (llength > 0)
		while (llength > 0) {
			*result = *ll;
			++result;
			++ll;
			--llength;
		}
	else
		while (rlength > 0) {
			*result = *rr;
			++result;
			++rr;
			--rlength;
		}

	free(ltmp);
	free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
        uint32_t salt, uint64_t key) {
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

void enc_table_init(const char *pass) {
    uint32_t i;
    uint32_t salt;
    uint64_t key = 0;
    uint8_t *digest;

    enc_table = malloc(256);
    dec_table = malloc(256);

    digest = MD5((const uint8_t *)pass, strlen(pass), NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }

    for(i = 0; i < 256; ++i) {
        enc_table[i] = i;
    }
    for(i = 1; i < 1024; ++i) {
        salt = i;
        merge_sort(enc_table, 256, salt, key);
    }
    for(i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        dec_table[enc_table[i]] = i;
    }
}

char* encrypt(char *plaintext, ssize_t *len, struct enc_ctx *ctx) {
    if (ctx != NULL) {
        int c_len = *len + BLOCK_SIZE;
        int iv_len = ctx->iv_len;
        char *ciphertext = malloc(max(iv_len + c_len, BUF_SIZE));

        if (!ctx->init) {
            uint8_t iv[EVP_MAX_IV_LENGTH];
            int i;
            for (i = 0; i < iv_len; i++) {
                iv[i] = rand() % 256;
            }
            EVP_CipherInit_ex(&ctx->evp, NULL, NULL, ctx->key, iv, 1);
            memcpy(ciphertext, iv, iv_len);
            ctx->iv_len = 0;
            ctx->init = 1;
#ifdef DEBUG
            dump("IV", ctx->iv);
#endif
        }

        EVP_EncryptUpdate(&ctx->evp, (uint8_t*)(ciphertext+iv_len), 
                &c_len, (const uint8_t *)plaintext, *len);

#ifdef DEBUG
        dump("PLAIN", plaintext);
        dump("CIPHER", ciphertext);
#endif

        *len = iv_len + c_len;
        free(plaintext);
        return ciphertext;
    } else {
        char *begin = plaintext;
        while (plaintext < begin + *len) {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
    }
}

char* decrypt(char *ciphertext, ssize_t *len, struct enc_ctx *ctx) {
    if (ctx != NULL) {
        int p_len = *len + BLOCK_SIZE;
        int iv_len = ctx->iv_len;
        char *plaintext = malloc(max(p_len, BUF_SIZE));

        if (!ctx->init) {
            uint8_t iv[EVP_MAX_IV_LENGTH];
            memcpy(iv, ciphertext, iv_len);
            EVP_CipherInit_ex(&ctx->evp, NULL, NULL, ctx->key, iv, 0);
            ctx->iv_len = 0;
            ctx->init = 1;
#ifdef DEBUG
            dump("IV", ctx->iv);
#endif
        }

        EVP_DecryptUpdate(&ctx->evp, (uint8_t*)plaintext, &p_len,
                (const uint8_t*)(ciphertext + iv_len), *len - iv_len);

#ifdef DEBUG
        dump("PLAIN", plaintext);
        dump("CIPHER", ciphertext);
#endif

        *len = p_len;
        free(ciphertext);
        return plaintext;
    } else {
        char *begin = ciphertext;
        while (ciphertext < begin + *len) {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
    }
}

void enc_ctx_init(int method, struct enc_ctx *ctx, int enc) {
    uint8_t *key = ctx->key;
    uint8_t iv[EVP_MAX_IV_LENGTH];
    int key_len;

    memset(ctx, 0, sizeof(struct enc_ctx));

    EVP_CIPHER_CTX *evp = &ctx->evp;
    OpenSSL_add_all_algorithms();
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(supported_ciphers[method]);
    ctx->iv_len = EVP_CIPHER_iv_length(cipher);

    key_len = EVP_BytesToKey(cipher, EVP_md5(), NULL, (uint8_t *)enc_pass, 
            strlen(enc_pass), 1, key, iv);

    EVP_CIPHER_CTX_init(evp);
    EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc);
    if (!EVP_CIPHER_CTX_set_key_length(evp, key_len)) {
        EVP_CIPHER_CTX_cleanup(evp);
        LOGE("Invalid key length: %d", key_len);
        exit(EXIT_FAILURE);
    }
    EVP_CIPHER_CTX_set_padding(evp, 1);
}

int enc_init(const char *pass, const char *method) {
    enc_pass = strdup(pass);
    if (method == NULL || strcmp(method, "table") == 0) {
        enc_table_init(enc_pass);
        return TABLE;
    } else if (strcmp(method, "aes-128-cfb") == 0) {
        return AES_128_CFB;
    } else if (strcmp(method, "aes-192-cfb") == 0) {
        return AES_192_CFB;
    } else if (strcmp(method, "aes-256-cfb") == 0) {
        return AES_256_CFB;
    } else if (strcmp(method, "bf-cfb") == 0) {
        return BF_CFB;
    } else if (strcmp(method, "cast5-cfb") == 0) {
        return CAST5_CFB;
    } else if (strcmp(method, "des-cfb") == 0) {
        return DES_CFB;
    } else if (strcmp(method, "rc4") == 0) {
        return RC4;
    }
    return TABLE;
}

