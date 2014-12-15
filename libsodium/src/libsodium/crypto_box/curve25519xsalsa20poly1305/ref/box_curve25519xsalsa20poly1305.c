#include "api.h"

int crypto_box(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[crypto_box_BEFORENMBYTES];
  crypto_box_beforenm(k,pk,sk);
  return crypto_box_afternm(c,m,mlen,n,k);
}

int crypto_box_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char k[crypto_box_BEFORENMBYTES];
  crypto_box_beforenm(k,pk,sk);
  return crypto_box_open_afternm(m,c,clen,n,k);
}
