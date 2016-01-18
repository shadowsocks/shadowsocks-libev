/*
   BLAKE2 reference source code package - C implementations

   Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "blake2.h"
#include "blake2-impl.h"
#include "runtime.h"

#ifdef HAVE_TI_MODE
# if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
# else
typedef unsigned uint128_t __attribute__((mode(TI)));
# endif
#endif

static blake2b_compress_fn blake2b_compress = blake2b_compress_ref;

static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/* LCOV_EXCL_START */
static inline int blake2b_set_lastnode( blake2b_state *S )
{
  S->f[1] = -1;
  return 0;
}
/* LCOV_EXCL_STOP */
#if 0
static inline int blake2b_clear_lastnode( blake2b_state *S )
{
  S->f[1] = 0;
  return 0;
}
#endif

static inline int blake2b_set_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_set_lastnode( S );

  S->f[0] = -1;
  return 0;
}
#if 0
static inline int blake2b_clear_lastblock( blake2b_state *S )
{
  if( S->last_node ) blake2b_clear_lastnode( S );

  S->f[0] = 0;
  return 0;
}
#endif
static inline int blake2b_increment_counter( blake2b_state *S, const uint64_t inc )
{
#ifdef HAVE_TI_MODE
  uint128_t t = ( ( uint128_t )S->t[1] << 64 ) | S->t[0];
  t += inc;
  S->t[0] = ( uint64_t )( t >>  0 );
  S->t[1] = ( uint64_t )( t >> 64 );
#else
  S->t[0] += inc;
  S->t[1] += ( S->t[0] < inc );
#endif
  return 0;
}

// Parameter-related functions
#if 0
static inline int blake2b_param_set_digest_length( blake2b_param *P, const uint8_t digest_length )
{
  P->digest_length = digest_length;
  return 0;
}

static inline int blake2b_param_set_fanout( blake2b_param *P, const uint8_t fanout )
{
  P->fanout = fanout;
  return 0;
}

static inline int blake2b_param_set_max_depth( blake2b_param *P, const uint8_t depth )
{
  P->depth = depth;
  return 0;
}

static inline int blake2b_param_set_leaf_length( blake2b_param *P, const uint32_t leaf_length )
{
  store32( &P->leaf_length, leaf_length );
  return 0;
}

static inline int blake2b_param_set_node_offset( blake2b_param *P, const uint64_t node_offset )
{
  store64( &P->node_offset, node_offset );
  return 0;
}

static inline int blake2b_param_set_node_depth( blake2b_param *P, const uint8_t node_depth )
{
  P->node_depth = node_depth;
  return 0;
}

static inline int blake2b_param_set_inner_length( blake2b_param *P, const uint8_t inner_length )
{
  P->inner_length = inner_length;
  return 0;
}
#endif
static inline int blake2b_param_set_salt( blake2b_param *P, const uint8_t salt[BLAKE2B_SALTBYTES] )
{
  memcpy( P->salt, salt, BLAKE2B_SALTBYTES );
  return 0;
}

static inline int blake2b_param_set_personal( blake2b_param *P, const uint8_t personal[BLAKE2B_PERSONALBYTES] )
{
  memcpy( P->personal, personal, BLAKE2B_PERSONALBYTES );
  return 0;
}

static inline int blake2b_init0( blake2b_state *S )
{
  int i;
  memset( S, 0, sizeof( blake2b_state ) );

  for( i = 0; i < 8; ++i ) S->h[i] = blake2b_IV[i];

  return 0;
}

/* init xors IV with input parameter block */
int blake2b_init_param( blake2b_state *S, const blake2b_param *P )
{
  size_t i;
  const uint8_t *p;

  blake2b_init0( S );
  p = ( const uint8_t * )( P );

  /* IV XOR ParamBlock */
  for( i = 0; i < 8; ++i )
    S->h[i] ^= load64( p + sizeof( S->h[i] ) * i );

  return 0;
}

int blake2b_init( blake2b_state *S, const uint8_t outlen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) abort();

  P->digest_length = outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );
  return blake2b_init_param( S, P );
}

int blake2b_init_salt_personal( blake2b_state *S, const uint8_t outlen,
                                const void *salt, const void *personal )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) abort();

  P->digest_length = outlen;
  P->key_length    = 0;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  if (salt != NULL) {
    blake2b_param_set_salt( P, (const uint8_t *) salt );
  } else {
    memset( P->salt, 0, sizeof( P->salt ) );
  }
  if (personal != NULL) {
    blake2b_param_set_personal( P, (const uint8_t *) personal );
  } else {
    memset( P->personal, 0, sizeof( P->personal ) );
  }
  return blake2b_init_param( S, P );
}

int blake2b_init_key( blake2b_state *S, const uint8_t outlen, const void *key, const uint8_t keylen )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) abort();

  if ( !key || !keylen || keylen > BLAKE2B_KEYBYTES ) abort();

  P->digest_length = outlen;
  P->key_length    = keylen;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  memset( P->salt,     0, sizeof( P->salt ) );
  memset( P->personal, 0, sizeof( P->personal ) );

  if( blake2b_init_param( S, P ) < 0 ) abort();

  {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset( block, 0, BLAKE2B_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2b_update( S, block, BLAKE2B_BLOCKBYTES );
    secure_zero_memory( block, BLAKE2B_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

int blake2b_init_key_salt_personal( blake2b_state *S, const uint8_t outlen, const void *key, const uint8_t keylen,
                                    const void *salt, const void *personal )
{
  blake2b_param P[1];

  if ( ( !outlen ) || ( outlen > BLAKE2B_OUTBYTES ) ) abort();

  if ( !key || !keylen || keylen > BLAKE2B_KEYBYTES ) abort();

  P->digest_length = outlen;
  P->key_length    = keylen;
  P->fanout        = 1;
  P->depth         = 1;
  store32( &P->leaf_length, 0 );
  store64( &P->node_offset, 0 );
  P->node_depth    = 0;
  P->inner_length  = 0;
  memset( P->reserved, 0, sizeof( P->reserved ) );
  if (salt != NULL) {
    blake2b_param_set_salt( P, (const uint8_t *) salt );
  } else {
    memset( P->salt, 0, sizeof( P->salt ) );
  }
  if (personal != NULL) {
    blake2b_param_set_personal( P, (const uint8_t *) personal );
  } else {
    memset( P->personal, 0, sizeof( P->personal ) );
  }

  if( blake2b_init_param( S, P ) < 0 ) abort();

  {
    uint8_t block[BLAKE2B_BLOCKBYTES];
    memset( block, 0, BLAKE2B_BLOCKBYTES );
    memcpy( block, key, keylen );
    blake2b_update( S, block, BLAKE2B_BLOCKBYTES );
    secure_zero_memory( block, BLAKE2B_BLOCKBYTES ); /* Burn the key from stack */
  }
  return 0;
}

/* inlen now in bytes */
int blake2b_update( blake2b_state *S, const uint8_t *in, uint64_t inlen )
{
  while( inlen > 0 )
  {
    size_t left = S->buflen;
    size_t fill = 2 * BLAKE2B_BLOCKBYTES - left;

    if( inlen > fill )
    {
      memcpy( S->buf + left, in, fill ); // Fill buffer
      S->buflen += fill;
      blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
      blake2b_compress( S, S->buf ); // Compress
      memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, BLAKE2B_BLOCKBYTES ); // Shift buffer left
      S->buflen -= BLAKE2B_BLOCKBYTES;
      in += fill;
      inlen -= fill;
    }
    else // inlen <= fill
    {
      memcpy( S->buf + left, in, inlen );
      S->buflen += inlen; // Be lazy, do not compress
      in += inlen;
      inlen -= inlen;
    }
  }

  return 0;
}

int blake2b_final( blake2b_state *S, uint8_t *out, uint8_t outlen )
{
  if( !outlen || outlen > BLAKE2B_OUTBYTES ) {
    abort();
  }
  if( S->buflen > BLAKE2B_BLOCKBYTES )
  {
    blake2b_increment_counter( S, BLAKE2B_BLOCKBYTES );
    blake2b_compress( S, S->buf );
    S->buflen -= BLAKE2B_BLOCKBYTES;
    assert( S->buflen <= BLAKE2B_BLOCKBYTES );
    memcpy( S->buf, S->buf + BLAKE2B_BLOCKBYTES, S->buflen );
  }

  blake2b_increment_counter( S, S->buflen );
  blake2b_set_lastblock( S );
  memset( S->buf + S->buflen, 0, 2 * BLAKE2B_BLOCKBYTES - S->buflen ); /* Padding */
  blake2b_compress( S, S->buf );

#ifdef NATIVE_LITTLE_ENDIAN
  memcpy( out, &S->h[0], outlen );
#else
  {
    uint8_t buffer[BLAKE2B_OUTBYTES];
    int     i;

    for( i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
      store64( buffer + sizeof( S->h[i] ) * i, S->h[i] );
    memcpy( out, buffer, outlen );
  }
#endif
  return 0;
}

/* inlen, at least, should be uint64_t. Others can be size_t. */
int blake2b( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen )
{
  blake2b_state S[1];

  /* Verify parameters */
  if( NULL == in && inlen > 0 ) abort();

  if( NULL == out ) abort();

  if( !outlen || outlen > BLAKE2B_OUTBYTES ) abort();

  if( NULL == key && keylen > 0 ) abort();

  if( keylen > BLAKE2B_KEYBYTES ) abort();

  if( keylen > 0 )
  {
    if( blake2b_init_key( S, outlen, key, keylen ) < 0 ) abort();
  }
  else
  {
    if( blake2b_init( S, outlen ) < 0 ) abort();
  }

  blake2b_update( S, ( const uint8_t * )in, inlen );
  blake2b_final( S, out, outlen );
  return 0;
}

int blake2b_salt_personal( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen,
                           const void *salt, const void *personal )
{
  blake2b_state S[1];

  /* Verify parameters */
  if( NULL == in && inlen > 0 ) abort();

  if( NULL == out ) abort();

  if( !outlen || outlen > BLAKE2B_OUTBYTES ) abort();

  if( NULL == key && keylen > 0 ) abort();

  if( keylen > BLAKE2B_KEYBYTES ) abort();

  if( keylen > 0 )
  {
    if( blake2b_init_key_salt_personal( S, outlen, key, keylen, salt, personal ) < 0 ) abort();
  }
  else
  {
    if( blake2b_init_salt_personal( S, outlen, salt, personal ) < 0 ) abort();
  }

  blake2b_update( S, ( const uint8_t * )in, inlen );
  blake2b_final( S, out, outlen );
  return 0;
}

int
blake2b_pick_best_implementation(void)
{
#if (defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H) && defined(HAVE_SMMINTRIN_H)) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
  if (sodium_runtime_has_sse41()) {
    blake2b_compress = blake2b_compress_sse41;
    return 0;
  }
#endif
#if (defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64)))
  if (sodium_runtime_has_ssse3()) {
    blake2b_compress = blake2b_compress_ssse3;
    return 0;
  }
#endif
  blake2b_compress = blake2b_compress_ref;

  return 0;
}
