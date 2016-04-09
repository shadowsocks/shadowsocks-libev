
#include "core.h"
#include "crypto_generichash.h"
#include "crypto_onetimeauth.h"
#include "crypto_scalarmult.h"
#include "crypto_stream_chacha20.h"
#include "randombytes.h"
#include "runtime.h"
#include "utils.h"

static int initialized;

int
sodium_init(void)
{
    if (initialized != 0) {
        return 1;
    }
    _sodium_runtime_get_cpu_features();
    randombytes_stir();
    _sodium_alloc_init();
    _crypto_generichash_blake2b_pick_best_implementation();
    _crypto_onetimeauth_poly1305_pick_best_implementation();
    _crypto_scalarmult_curve25519_pick_best_implementation();
    _crypto_stream_chacha20_pick_best_implementation();
    initialized = 1;

    return 0;
}
