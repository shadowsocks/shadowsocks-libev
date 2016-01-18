#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "utils.h"

int crypto_box_curve25519xsalsa20poly1305(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
  int           ret;

  if (crypto_box_curve25519xsalsa20poly1305_beforenm(k,pk,sk) != 0) {
      return -1;
  }
  ret = crypto_box_curve25519xsalsa20poly1305_afternm(c,m,mlen,n,k);
  sodium_memzero(k, sizeof k);

  return ret;
}

int crypto_box_curve25519xsalsa20poly1305_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
  int           ret;

  if (crypto_box_curve25519xsalsa20poly1305_beforenm(k,pk,sk) != 0) {
      return -1;
  }
  ret = crypto_box_curve25519xsalsa20poly1305_open_afternm(m,c,clen,n,k);
  sodium_memzero(k, sizeof k);

  return ret;
}
