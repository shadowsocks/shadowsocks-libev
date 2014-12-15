noinst_LTLIBRARIES = \
	libsodium.la

libsodium_la_SOURCES = \
	crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c \
	crypto_auth/crypto_auth.c \
	crypto_auth/hmacsha256/auth_hmacsha256_api.c \
	crypto_auth/hmacsha256/cp/api.h \
	crypto_auth/hmacsha256/cp/hmac_hmacsha256.c \
	crypto_auth/hmacsha256/cp/verify_hmacsha256.c \
	crypto_auth/hmacsha512/auth_hmacsha512_api.c \
	crypto_auth/hmacsha512/cp/api.h \
	crypto_auth/hmacsha512/cp/hmac_hmacsha512.c \
	crypto_auth/hmacsha512/cp/verify_hmacsha512.c \
	crypto_auth/hmacsha512256/auth_hmacsha512256_api.c \
	crypto_auth/hmacsha512256/cp/api.h \
	crypto_auth/hmacsha512256/cp/hmac_hmacsha512256.c \
	crypto_auth/hmacsha512256/cp/verify_hmacsha512256.c \
	crypto_box/crypto_box.c \
	crypto_box/crypto_box_easy.c \
	crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c \
	crypto_box/curve25519xsalsa20poly1305/ref/api.h \
	crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c \
	crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c \
	crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c \
	crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c \
	crypto_core/hsalsa20/ref2/core_hsalsa20.c \
	crypto_core/hsalsa20/core_hsalsa20_api.c \
	crypto_core/hsalsa20/ref2/api.h \
	crypto_core/salsa20/ref/core_salsa20.c \
	crypto_core/salsa20/core_salsa20_api.c \
	crypto_core/salsa20/ref/api.h \
	crypto_generichash/crypto_generichash.c \
	crypto_generichash/blake2/generichash_blake2_api.c \
	crypto_generichash/blake2/ref/api.h \
	crypto_generichash/blake2/ref/blake2-impl.h \
	crypto_generichash/blake2/ref/blake2.h \
	crypto_generichash/blake2/ref/blake2b-ref.c \
	crypto_generichash/blake2/ref/generichash_blake2b.c \
	crypto_hash/crypto_hash.c \
	crypto_hash/sha256/hash_sha256_api.c \
	crypto_hash/sha256/cp/api.h \
	crypto_hash/sha256/cp/hash_sha256.c \
	crypto_hash/sha512/hash_sha512_api.c \
	crypto_hash/sha512/cp/api.h \
	crypto_hash/sha512/cp/hash_sha512.c \
	crypto_onetimeauth/crypto_onetimeauth.c \
	crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
	crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c \
	crypto_onetimeauth/poly1305/onetimeauth_poly1305_try.c \
	crypto_onetimeauth/poly1305/donna/poly1305_donna.h \
	crypto_onetimeauth/poly1305/donna/poly1305_donna32.h \
	crypto_onetimeauth/poly1305/donna/poly1305_donna64.h \
	crypto_onetimeauth/poly1305/donna/auth_poly1305_donna.c \
	crypto_onetimeauth/poly1305/donna/verify_poly1305_donna.c \
	crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c \
	crypto_pwhash/scryptsalsa208sha256/crypto_scrypt.h \
	crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c \
	crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c \
	crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.h \
	crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c \
	crypto_pwhash/scryptsalsa208sha256/sysendian.h \
	crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c \
	crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c \
	crypto_scalarmult/crypto_scalarmult.c \
	crypto_scalarmult/curve25519/scalarmult_curve25519_api.c \
	crypto_secretbox/crypto_secretbox.c \
	crypto_secretbox/crypto_secretbox_easy.c \
	crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c \
	crypto_secretbox/xsalsa20poly1305/ref/api.h \
	crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c \
	crypto_shorthash/crypto_shorthash.c \
	crypto_shorthash/siphash24/shorthash_siphash24_api.c \
	crypto_shorthash/siphash24/ref/api.h \
	crypto_shorthash/siphash24/ref/shorthash_siphash24.c \
	crypto_sign/crypto_sign.c \
	crypto_sign/ed25519/ref10/base.h \
	crypto_sign/ed25519/ref10/base2.h \
	crypto_sign/ed25519/sign_ed25519_api.c \
	crypto_sign/ed25519/ref10/api.h \
	crypto_sign/ed25519/ref10/d.h \
	crypto_sign/ed25519/ref10/d2.h \
	crypto_sign/ed25519/ref10/fe.h \
	crypto_sign/ed25519/ref10/fe_0.c \
	crypto_sign/ed25519/ref10/fe_1.c \
	crypto_sign/ed25519/ref10/fe_add.c \
	crypto_sign/ed25519/ref10/fe_cmov.c \
	crypto_sign/ed25519/ref10/fe_copy.c \
	crypto_sign/ed25519/ref10/fe_frombytes.c \
	crypto_sign/ed25519/ref10/fe_invert.c \
	crypto_sign/ed25519/ref10/fe_isnegative.c \
	crypto_sign/ed25519/ref10/fe_isnonzero.c \
	crypto_sign/ed25519/ref10/fe_mul.c \
	crypto_sign/ed25519/ref10/fe_neg.c \
	crypto_sign/ed25519/ref10/fe_pow22523.c \
	crypto_sign/ed25519/ref10/fe_sq.c \
	crypto_sign/ed25519/ref10/fe_sq2.c \
	crypto_sign/ed25519/ref10/fe_sub.c \
	crypto_sign/ed25519/ref10/fe_tobytes.c \
	crypto_sign/ed25519/ref10/ge.h \
	crypto_sign/ed25519/ref10/ge_add.c \
	crypto_sign/ed25519/ref10/ge_add.h \
	crypto_sign/ed25519/ref10/ge_double_scalarmult.c \
	crypto_sign/ed25519/ref10/ge_frombytes.c \
	crypto_sign/ed25519/ref10/ge_madd.c \
	crypto_sign/ed25519/ref10/ge_madd.h \
	crypto_sign/ed25519/ref10/ge_msub.c \
	crypto_sign/ed25519/ref10/ge_msub.h \
	crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c \
	crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c \
	crypto_sign/ed25519/ref10/ge_p2_0.c \
	crypto_sign/ed25519/ref10/ge_p2_dbl.c \
	crypto_sign/ed25519/ref10/ge_p2_dbl.h \
	crypto_sign/ed25519/ref10/ge_p3_0.c \
	crypto_sign/ed25519/ref10/ge_p3_dbl.c \
	crypto_sign/ed25519/ref10/ge_p3_to_cached.c \
	crypto_sign/ed25519/ref10/ge_p3_to_p2.c \
	crypto_sign/ed25519/ref10/ge_p3_tobytes.c \
	crypto_sign/ed25519/ref10/ge_precomp_0.c \
	crypto_sign/ed25519/ref10/ge_scalarmult_base.c \
	crypto_sign/ed25519/ref10/ge_sub.c \
	crypto_sign/ed25519/ref10/ge_sub.h \
	crypto_sign/ed25519/ref10/ge_tobytes.c \
	crypto_sign/ed25519/ref10/keypair.c \
	crypto_sign/ed25519/ref10/open.c \
	crypto_sign/ed25519/ref10/pow22523.h \
	crypto_sign/ed25519/ref10/pow225521.h \
	crypto_sign/ed25519/ref10/sc.h \
	crypto_sign/ed25519/ref10/sc_muladd.c \
	crypto_sign/ed25519/ref10/sc_reduce.c \
	crypto_sign/ed25519/ref10/sign.c \
	crypto_sign/ed25519/ref10/sqrtm1.h \
	crypto_stream/crypto_stream.c \
	crypto_stream/chacha20/stream_chacha20_api.c \
	crypto_stream/chacha20/ref/api.h \
	crypto_stream/chacha20/ref/stream_chacha20_ref.c \
	crypto_stream/salsa20/stream_salsa20_api.c \
	crypto_stream/xsalsa20/stream_xsalsa20_api.c \
	crypto_stream/xsalsa20/ref/api.h \
	crypto_stream/xsalsa20/ref/stream_xsalsa20.c \
	crypto_stream/xsalsa20/ref/xor_xsalsa20.c \
	crypto_verify/16/verify_16_api.c \
	crypto_verify/16/ref/api.h \
	crypto_verify/16/ref/verify_16.c \
	crypto_verify/32/verify_32_api.c \
	crypto_verify/32/ref/api.h \
	crypto_verify/32/ref/verify_32.c \
	crypto_verify/64/verify_64_api.c \
	crypto_verify/64/ref/api.h \
	crypto_verify/64/ref/verify_64.c \
	randombytes/randombytes.c \
	randombytes/salsa20/randombytes_salsa20_random.c \
	randombytes/sysrandom/randombytes_sysrandom.c \
	sodium/core.c \
	sodium/runtime.c \
	sodium/utils.c \
	sodium/version.c

if HAVE_TI_MODE
libsodium_la_SOURCES += \
	crypto_scalarmult/curve25519/donna_c64/api.h \
	crypto_scalarmult/curve25519/donna_c64/base_curve25519_donna_c64.c \
	crypto_scalarmult/curve25519/donna_c64/smult_curve25519_donna_c64.c
else
libsodium_la_SOURCES += \
	crypto_scalarmult/curve25519/ref10/api.h \
	crypto_scalarmult/curve25519/ref10/base_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe.h \
	crypto_scalarmult/curve25519/ref10/fe_0_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_1_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_add_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_copy_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_cswap_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_frombytes_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_invert_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_mul_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_mul121666_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_sq_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_sub_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/fe_tobytes_curve25519_ref10.c \
	crypto_scalarmult/curve25519/ref10/montgomery.h \
	crypto_scalarmult/curve25519/ref10/pow225521.h \
	crypto_scalarmult/curve25519/ref10/scalarmult_curve25519_ref10.c
endif

if HAVE_AMD64_ASM
libsodium_la_SOURCES += \
	crypto_stream/salsa20/amd64_xmm6/api.h \
	crypto_stream/salsa20/amd64_xmm6/stream_salsa20_amd64_xmm6.S
else
libsodium_la_SOURCES += \
	crypto_stream/salsa20/ref/api.h \
	crypto_stream/salsa20/ref/stream_salsa20_ref.c \
	crypto_stream/salsa20/ref/xor_salsa20_ref.c
endif

if !MINIMAL
libsodium_la_SOURCES += \
	crypto_core/salsa2012/ref/core_salsa2012.c \
	crypto_core/salsa2012/core_salsa2012_api.c \
	crypto_core/salsa2012/ref/api.h \
	crypto_core/salsa208/ref/core_salsa208.c \
	crypto_core/salsa208/core_salsa208_api.c \
	crypto_core/salsa208/ref/api.h \
	crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c \
	crypto_sign/edwards25519sha512batch/ref/api.h \
	crypto_sign/edwards25519sha512batch/ref/fe25519.h \
	crypto_sign/edwards25519sha512batch/ref/fe25519_edwards25519sha512batch.c \
	crypto_sign/edwards25519sha512batch/ref/ge25519.h \
	crypto_sign/edwards25519sha512batch/ref/ge25519_edwards25519sha512batch.c \
	crypto_sign/edwards25519sha512batch/ref/sc25519.h \
	crypto_sign/edwards25519sha512batch/ref/sc25519_edwards25519sha512batch.c \
	crypto_sign/edwards25519sha512batch/ref/sign_edwards25519sha512batch.c \
	crypto_stream/aes128ctr/portable/afternm_aes128ctr.c \
	crypto_stream/aes128ctr/stream_aes128ctr_api.c \
	crypto_stream/aes128ctr/portable/api.h \
	crypto_stream/aes128ctr/portable/beforenm_aes128ctr.c \
	crypto_stream/aes128ctr/portable/common.h \
	crypto_stream/aes128ctr/portable/common_aes128ctr.c \
	crypto_stream/aes128ctr/portable/consts.h \
	crypto_stream/aes128ctr/portable/consts_aes128ctr.c \
	crypto_stream/aes128ctr/portable/int128.h \
	crypto_stream/aes128ctr/portable/int128_aes128ctr.c \
	crypto_stream/aes128ctr/portable/stream_aes128ctr.c \
	crypto_stream/aes128ctr/portable/types.h \
	crypto_stream/aes128ctr/portable/xor_afternm_aes128ctr.c \
	crypto_stream/salsa2012/stream_salsa2012_api.c \
	crypto_stream/salsa2012/ref/api.h \
	crypto_stream/salsa2012/ref/stream_salsa2012.c \
	crypto_stream/salsa2012/ref/xor_salsa2012.c \
	crypto_stream/salsa208/stream_salsa208_api.c \
	crypto_stream/salsa208/ref/api.h \
	crypto_stream/salsa208/ref/stream_salsa208.c \
	crypto_stream/salsa208/ref/xor_salsa208.c
endif

libsodium_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-export-dynamic \
	-no-undefined \
	$(LIBTOOL_EXTRA_FLAGS)

libsodium_la_CPPFLAGS = \
	$(LTDLINCL) \
	-I$(srcdir)/include/sodium \
	-I$(builddir)/include/sodium

if HAVE_LD_OUTPUT_DEF
libsodium_la_LDFLAGS += -Wl,--output-def,libsodium-$(DLL_VERSION).def
defexecdir = $(bindir)
defexec_DATA = libsodium-$(DLL_VERSION).def
CLEANFILES = $(defexec_DATA)
libsodium-$(DLL_VERSION).def: libsodium.la
endif

SUBDIRS = \
	include
