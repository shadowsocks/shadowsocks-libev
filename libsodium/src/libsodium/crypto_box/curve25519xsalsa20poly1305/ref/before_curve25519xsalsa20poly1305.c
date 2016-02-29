#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_core_hsalsa20.h"
#include "crypto_scalarmult_curve25519.h"

static const unsigned char sigma[16] = {
    'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};
static const unsigned char n[16] = {0};

int crypto_box_curve25519xsalsa20poly1305_beforenm(
  unsigned char *k,
  const unsigned char *pk,
  const unsigned char *sk
)
{
  unsigned char s[32];
  if (crypto_scalarmult_curve25519(s,sk,pk) != 0) {
      return -1;
  }
  return crypto_core_hsalsa20(k,n,s,sigma);
}
