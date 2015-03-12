/*
 * bitcoin.c
 *
 * Copyright (C) 2015, Kevin Pan <bit.kevin@gmail.com>
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
#include "bitcoin.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

//
// address prefix
// @see https://en.bitcoin.it/wiki/List_of_address_prefixes
//
#define BITCOIN_ADDRESS_PREFIX_PUBKEY         0x00
#define BITCOIN_ADDRESS_PREFIX_PUBKEY_TESTNET 0x6F

#define BITCOIN_PUBKEY_UNCOMPRESSED 0x00
#define BITCOIN_PUBKEY_COMPRESSED   0x01


#define skip_char(c) \
(((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

const char *vg_b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const signed char vg_b58_reverse_map[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};


static int vg_b58_decode_check(const char *input, void *buf, size_t len) {
    int i, l, c;
    unsigned char *xbuf = NULL;
    BIGNUM bn, bnw, bnbase;
    BN_CTX *bnctx;
    unsigned char hash1[32], hash2[32];
    int zpfx;
    int res = 0;

    BN_init(&bn);
    BN_init(&bnw);
    BN_init(&bnbase);
    BN_set_word(&bnbase, 58);
    bnctx = BN_CTX_new();

    /* Build a bignum from the encoded value */
    l = strlen(input);
    for (i = 0; i < l; i++) {
        if (skip_char(input[i]))
            continue;
        c = vg_b58_reverse_map[(int)input[i]];
        if (c < 0)
            goto out;
        BN_clear(&bnw);
        BN_set_word(&bnw, c);
        BN_mul(&bn, &bn, &bnbase, bnctx);
        BN_add(&bn, &bn, &bnw);
    }

    /* Copy the bignum to a byte buffer */
    for (i = 0, zpfx = 0; input[i]; i++) {
        if (skip_char(input[i]))
            continue;
        if (input[i] != vg_b58_alphabet[0])
            break;
        zpfx++;
    }
    c = BN_num_bytes(&bn);
    l = zpfx + c;
    if (l < 5)
        goto out;
    xbuf = (unsigned char *) malloc(l);
    if (!xbuf)
        goto out;
    if (zpfx)
        memset(xbuf, 0, zpfx);
    if (c)
        BN_bn2bin(&bn, xbuf + zpfx);

    /* Check the hash code */
    l -= 4;
    SHA256(xbuf, l, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    if (memcmp(hash2, xbuf + l, 4))
        goto out;
    /* Buffer verified */
    if (len) {
        if (len > l)
            len = l;
        memcpy(buf, xbuf, len);
    }
    res = l;

out:
    if (xbuf)
        free(xbuf);
    BN_clear_free(&bn);
    BN_clear_free(&bnw);
    BN_clear_free(&bnbase);
    BN_CTX_free(bnctx);
    return res;
}

static void vg_b58_encode_check(void *buf, size_t len, char *result)
{
    unsigned char hash1[32];
    unsigned char hash2[32];

    int d, p;

    BN_CTX *bnctx;
    BIGNUM *bn, *bndiv, *bntmp;
    BIGNUM bna, bnb, bnbase, bnrem;
    unsigned char *binres;
    int brlen, zpfx;

    bnctx = BN_CTX_new();
    BN_init(&bna);
    BN_init(&bnb);
    BN_init(&bnbase);
    BN_init(&bnrem);
    BN_set_word(&bnbase, 58);

    bn = &bna;
    bndiv = &bnb;

    brlen = (2 * len) + 4;
    binres = (unsigned char*) malloc(brlen);
    memcpy(binres, buf, len);

    SHA256(binres, len, hash1);
    SHA256(hash1, sizeof(hash1), hash2);
    memcpy(&binres[len], hash2, 4);

    BN_bin2bn(binres, len + 4, bn);

    for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++);

    p = (int)brlen;
    while (!BN_is_zero(bn)) {
        BN_div(bndiv, &bnrem, bn, &bnbase, bnctx);
        bntmp = bn;
        bn = bndiv;
        bndiv = bntmp;
        d = BN_get_word(&bnrem);
        binres[--p] = vg_b58_alphabet[d];
    }

    while (zpfx--) {
        binres[--p] = vg_b58_alphabet[0];
    }

    memcpy(result, &binres[p], brlen - p);
    result[brlen - p] = '\0';
    
    free(binres);
    BN_clear_free(&bna);
    BN_clear_free(&bnb);
    BN_clear_free(&bnbase);
    BN_clear_free(&bnrem);
    BN_CTX_free(bnctx);
}

static void vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
                              point_conversion_form_t form, int addr_type, char *result)
{
    unsigned char eckey_buf[128] = {0};
    unsigned char binres[21] = {0,};
    unsigned char hash1[32];
    size_t len = 0;

    len = EC_POINT_point2oct(pgroup, ppoint, form,
                             eckey_buf, sizeof(eckey_buf), NULL);
    binres[0] = addr_type;
    SHA256(eckey_buf, len, hash1);
    RIPEMD160(hash1, sizeof(hash1), &binres[1]);

    vg_b58_encode_check(binres, sizeof(binres), result);
}

static size_t write_compact_size(const uint64_t val, uint8_t *dest) {
    if (val < 0xfd) {
        *dest++ = (unsigned char)val;
        return 1;
    } else if (val <= 0xffff) {
        *dest++ = 0xfd;
        *(uint16_t *)dest = (uint16_t)val;
        return 2;
    } else if (val <= 0xffffffff) {
        *dest++ = 0xfe;
        *(uint32_t *)dest = (uint32_t)val;
        return 4;
    } else {
        *dest++ = 0xff;
        *(uint64_t *)dest = (uint64_t)val;
        return 8;
    }
    return 0;
}

static void dsha265_message(uint8_t *hash,
                            const uint8_t *msg, const size_t len_msg) {
    const char *magic = "Bitcoin Signed Message:\n";  // bitcoin message magic
    const size_t len_magic = strlen(magic);
    size_t buf_size = len_magic + len_msg + 9/*max_compact_size*/ * 2;

    char *buf = (char *)malloc(buf_size);
    size_t buf_len = 0;
    memset(buf, 0, buf_size);

    buf_len += write_compact_size(len_magic, (uint8_t *)buf);
    memcpy(buf + buf_len, magic, len_magic);
    buf_len += len_magic;

    buf_len += write_compact_size(len_msg, (uint8_t *)buf + buf_len);
    memcpy(buf + buf_len, msg, len_msg);
    buf_len += len_msg;
    assert(buf_len <= buf_size);

    uint8_t hash1[32];
    SHA256((uint8_t *)buf, buf_len, hash1);
    SHA256(hash1, sizeof(hash1), hash);
    free(buf);
}

static int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key) {
    int ok = 0;
    BN_CTX *ctx = NULL;
    EC_POINT *pub_key = NULL;

    if (!eckey) return 0;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    pub_key = EC_POINT_new(group);
    if (pub_key == NULL)
        goto err;

    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey,priv_key);
    EC_KEY_set_public_key(eckey,pub_key);
    ok = 1;

err:
    if (pub_key)
        EC_POINT_free(pub_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return ok;
}

// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
static int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig,
                                     const unsigned char *msg,
                                     int msglen, int recid, int check) {
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check) {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) { ret=-1; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

static int priv_key_b58_to_address(const char *priv_key_b58,
                                   const int is_compressed_pubkey,
                                   const int addr_type,
                                   char *address) {
    EC_KEY *pkey   = NULL;
    unsigned char buf[128] = {0};
    uint8_t pubKey[65];  // public key max size is 65 bytes
    char ecprot[128];
    unsigned char *pbegin  = NULL;
    int res, pubkey_size = 0;
    int fOk = 0;

    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_conv_form(pkey, is_compressed_pubkey ?
                         POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

    // import secret
    vg_b58_decode_check(priv_key_b58, buf, 33);
    BIGNUM *bn = BN_bin2bn(buf + 1, 32, BN_new());
    res = EC_KEY_regenerate_key(pkey, bn);
    BN_clear_free(bn);
    if (!res){ goto error; }

    // get pubkey
    pubkey_size = i2o_ECPublicKey(pkey, NULL);
    if (!pubkey_size) { goto error; }
    pbegin = pubKey;
    if (i2o_ECPublicKey(pkey, &pbegin) != pubkey_size) { goto error; }

    // encode address
    vg_encode_address(EC_KEY_get0_public_key(pkey),
                      EC_KEY_get0_group(pkey),
                      is_compressed_pubkey ?
                      POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                      addr_type, ecprot);
    strcpy(address, ecprot);
    fOk = 1;

error:
    if (pkey) { EC_KEY_free(pkey); }
    return fOk;
}

//
// return:
//   -1 : invalid private key
//    1 : compressed
//    0 : uncompressed
static int isCompressedAddress(const char *priv_key_b58, const char *address) {
    int is_compressed_pubkey;
    char buf[64];
    int res;

    // try compressed
    is_compressed_pubkey = 1;
    memset(buf, 0, sizeof(buf));
    res = priv_key_b58_to_address(priv_key_b58, is_compressed_pubkey,
                                  BITCOIN_ADDRESS_PREFIX_PUBKEY, buf);
    if (res != 1) { return -1; }
    if (memcmp(buf, address, strlen(address)) == 0) {
        return 1;  // compressed
    }

    // try uncompressed
    is_compressed_pubkey = 0;
    memset(buf, 0, sizeof(buf));
    res = priv_key_b58_to_address(priv_key_b58, is_compressed_pubkey,
                                  BITCOIN_ADDRESS_PREFIX_PUBKEY, buf);
    if (res != 1) { return -1; }
    if (memcmp(buf, address, strlen(address)) == 0) {
        return 0;  // uncompressed
    }

    return -1;
}

static int sign_message(uint8_t *signature_65,
                        const uint8_t *msg, const size_t msg_len,
                        const char *priv_key_b58, int is_compressed_pubkey) {
    EC_KEY *pkey   = NULL;
    ECDSA_SIG *sig = NULL;
    EC_KEY *eckey  = NULL;  // recover key

    uint8_t pubKey[65];  // public key max size is 65 bytes
    uint8_t pubKey_rc[65];
    int pubkey_size, pubkey_rc_size;
    uint8_t sigbuf[65];

    unsigned char *pbegin = NULL;
    unsigned char buf[128] = {0};
    int res, fOK = 0;
    int nBitsR, nBitsS;
    unsigned char hash[32];

    dsha265_message(hash, msg, msg_len);  // message double sha256

    pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_conv_form(pkey, is_compressed_pubkey ?
                         POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

    // import secret
    vg_b58_decode_check(priv_key_b58, buf, 33);
    BIGNUM *bn = BN_bin2bn(buf + 1, 32, BN_new());
    res = EC_KEY_regenerate_key(pkey, bn);
    BN_clear_free(bn);
    memset(buf, 0, sizeof(buf));
    if (!res){ goto error; }

    // get pubkey
    pubkey_size = i2o_ECPublicKey(pkey, NULL);
    if (!pubkey_size) { goto error; }

    pbegin = pubKey;
    if (i2o_ECPublicKey(pkey, &pbegin) != pubkey_size) { goto error; }
    
    // do sign
    sig = ECDSA_do_sign(hash, sizeof(hash), pkey);
    if (!sig) { goto error; }

    nBitsR = BN_num_bits(sig->r);
    nBitsS = BN_num_bits(sig->s);

    if (nBitsR <= 256 && nBitsS <= 256) {
        int nRecId = -1;
        int i;
        eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
        EC_KEY_set_conv_form(eckey, is_compressed_pubkey ?
                             POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);

        for (i = 0; i < 4; i++) {
            if (ECDSA_SIG_recover_key_GFp(eckey, sig, (unsigned char*)hash,
                                          sizeof(hash), i, 1) == 1) {
                // get recover pubkey
                pubkey_rc_size = i2o_ECPublicKey(pkey, NULL);
                if (!pubkey_rc_size) { goto error; }

                pbegin = pubKey_rc;
                if (i2o_ECPublicKey(eckey, &pbegin) != pubkey_rc_size) {
                    goto error;
                }
                // check recover key
                if (pubkey_size == pubkey_rc_size &&
                    memcmp(pubKey, pubKey_rc, pubkey_rc_size) == 0) {
                    nRecId = i;
                    break;
                }
            }
        }
        if (nRecId == -1) { goto error; }

        sigbuf[0] = nRecId + 27 + (is_compressed_pubkey ? 4 : 0);
        BN_bn2bin(sig->r, sigbuf + 33 - (nBitsR+7)/8);
        BN_bn2bin(sig->s, sigbuf + 65 - (nBitsS+7)/8);

        memcpy(signature_65, sigbuf, 65);
        fOK = 1;
    }
    
error:
    if (pkey)  { EC_KEY_free(pkey); }
    if (eckey) { EC_KEY_free(eckey); }
    if (sig)   { ECDSA_SIG_free(sig); }
    
    return fOK;
}


int bitcoin_sign_message(unsigned char *buf_65,
                         const void *msg, const size_t msg_len,
                         const char *priv_key_b58, const char *address) {
    int is_compressed = isCompressedAddress(priv_key_b58, address);
    return sign_message(buf_65, (uint8_t *)msg, msg_len,
                        priv_key_b58, is_compressed);
}

int bitcoin_verify_message(const char *address, const unsigned char *sig,
                           const void *msg, const size_t msglen) {
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    uint8_t hash[32] = {0};
    char ecprot[128] = {0};
    int fOK = 0;

    // message double sha256
    dsha265_message(hash, msg, msglen);

    // recover
    ECDSA_SIG *esig = ECDSA_SIG_new();
    BN_bin2bn(&sig[1],  32, esig->r);
    BN_bin2bn(&sig[33], 32, esig->s);
    int ret = ECDSA_SIG_recover_key_GFp(pkey, esig, hash, sizeof(hash),
                                        ((sig[0] - 27) & ~4), 0) == 1;
    ECDSA_SIG_free(esig);
    if (!ret) { goto error; }

    int is_compressed_pubkey = (sig[0] - 27) & 4;
    // encode address
    vg_encode_address(EC_KEY_get0_public_key(pkey),
                      EC_KEY_get0_group(pkey),
                      is_compressed_pubkey ?
                      POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
                      BITCOIN_ADDRESS_PREFIX_PUBKEY, ecprot);
    if (memcmp(address, ecprot, strlen(address)) == 0) {
        fOK = 1;
    }

error:
    if (pkey) { EC_KEY_free(pkey); }
    return fOK;
}



struct btc_client {
    char address[36];
};
struct btc_list {
    struct btc_client *clients;
    size_t number;
    char *file;
    pthread_rwlock_t lock;
    pthread_t        thread;
    int running;
};

static int cmp_btc_client(const void *l, const void *r) {
    struct btc_client *pl = (struct btc_client *)l;
    struct btc_client *pr = (struct btc_client *)r;
    return strcmp(pl->address, pr->address);
}

extern struct btc_list *bitcoin_init_list(const char *file) {
    struct btc_list *l = calloc(1, sizeof(struct btc_list));
    l->clients = NULL;
    pthread_rwlock_init(&l->lock, NULL);
    l->number  = 0;
    l->file    = strdup(file);
    l->running = 1;
    return l;
}

static void *check_list(void *ptr) {
    struct btc_list *list = (struct btc_list *)ptr;
    time_t last_check_time  = 0;
    time_t last_modify_time = 0;

    struct stat attrib;
    size_t size = 8;
    char line[64];
    int running = 1;

    while (1) {
        pthread_rwlock_rdlock(&list->lock);
        running = list->running;
        pthread_rwlock_unlock(&list->lock);

        if (running == 0) {
            break;  // stop thread
        }

        // update when: 1. last check time over than 10 seconds
        //              2. file has been modified
        if (time(NULL) < last_check_time + 10) {
            sleep(1);
            continue;
        }
        last_check_time = time(NULL);

        if (stat(list->file, &attrib) != 0) {
            continue;
        }
        if (last_modify_time == attrib.st_mtime) {
            continue;
        }

        FILE *f = fopen(list->file, "rb");
        if (f == NULL) {
            continue;
        }
        if (flock(fileno(f), LOCK_EX | LOCK_NB) != 0) {
            fclose(f);
            continue;
        }

        size_t idx  = 0;
        struct btc_client *clients = calloc(size, sizeof(struct btc_client));
        while (fgets(line, sizeof(line), f)) {
            while (strlen(line) > 0 && !isalpha(line[strlen(line) - 1])) {
                line[strlen(line) - 1] = '\0';
            }
            if (strlen(line) > 35 || strlen(line) < 26) {
                continue;  // bitcoin address length range: [26, 35]
            }
            if (idx >= size) {
                size *= 2;
                clients = realloc(clients, size * sizeof(struct btc_client));
            }
            struct btc_client *c = clients + idx;
            strcpy(c->address, line);
            idx++;
        }
        fclose(f);
        flock(fileno(f), LOCK_UN);

        assert(idx <= size);
        if (idx == 0) {
            free(clients);
            clients = NULL;
        } else {
            if (idx != size) {
                clients = realloc(clients, idx * sizeof(struct btc_client));
            }
            qsort(clients, idx, sizeof(struct btc_client), cmp_btc_client);
        }

        // update list
        pthread_rwlock_wrlock(&list->lock);
        if (list->clients != NULL) {
            free(list->clients);
        }
        list->clients = clients;
        list->number  = idx;
        pthread_rwlock_unlock(&list->lock);

        last_modify_time = attrib.st_mtime;
    }

    return NULL;
}

extern int bitcoin_setup_update_thread(struct btc_list *list) {
    if (pthread_create(&list->thread, NULL, check_list, list) == 0) {
        return 1;
    }
    return 0;  // error
}

extern void bitcoin_clean_update_thread(struct btc_list *list) {
    pthread_rwlock_wrlock(&list->lock);
    list->running = 0;
    pthread_rwlock_unlock(&list->lock);

    pthread_join(list->thread, NULL);
}

extern int bitcoin_check_address(struct btc_list *list,
                                 const char *address) {
    struct btc_client key, *res = NULL;
    memset(&key, 0, sizeof(struct btc_client));
    strncpy(key.address, address, 35);

    pthread_rwlock_rdlock(&list->lock);
    if (list->number > 0) {
        res = bsearch(&key, list->clients, list->number,
                      sizeof(struct btc_client), cmp_btc_client);
    }
    pthread_rwlock_unlock(&list->lock);

    if (res != NULL) {
        return 1;
    }
    return 0;
}
