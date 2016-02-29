AC_PREREQ([2.65])
AC_INIT([libsodium],[1.0.7],
  [https://github.com/jedisct1/libsodium/issues],
  [libsodium],
  [https://github.com/jedisct1/libsodium])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/libsodium/sodium/version.c])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.11 dist-bzip2 tar-ustar foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_MAINTAINER_MODE
AM_DEP_TRACK

AC_SUBST(VERSION)
ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

SODIUM_LIBRARY_VERSION_MAJOR=9
SODIUM_LIBRARY_VERSION_MINOR=0
DLL_VERSION=8
SODIUM_LIBRARY_VERSION=18:0:0
#                       | | |
#                +------+ | +---+
#                |        |     |
#             current:revision:age
#                |        |     |
#                |        |     +- increment if interfaces have been added
#                |        |        set to zero if interfaces have been removed
#                |        |        or changed
#                |        +- increment if source code has changed
#                |           set to zero if current is incremented
#                +- increment if interfaces have been added, removed or changed
AC_SUBST(SODIUM_LIBRARY_VERSION_MAJOR)
AC_SUBST(SODIUM_LIBRARY_VERSION_MINOR)
AC_SUBST(SODIUM_LIBRARY_VERSION)
AC_SUBST(DLL_VERSION)

LX_CFLAGS=${CFLAGS-NONE}

dnl Path check

AS_IF([test pwd | fgrep ' ' > /dev/null 2>&1],
  [AC_MSG_WARN([The build directory contains whitespaces - This can cause tests/installation to fail due to limitations of some libtool versions])]
)

dnl Switches

AC_ARG_ENABLE(ssp,
[AS_HELP_STRING(--disable-ssp,Do not compile with -fstack-protector)],
[
  AS_IF([test "x$enableval" = "xno"], [
    enable_ssp="no"
  ], [
    enable_ssp="yes"
  ])
],
[
  enable_ssp="yes"
])

AC_ARG_ENABLE(asm,
[AS_HELP_STRING(--disable-asm,Disable assembly implementations)],
[
  AS_IF([test "x$enableval" = "xno"], [
    enable_asm="no"
  ], [
    enable_asm="yes"
  ])
],
[
  enable_asm="yes"
])

AS_IF([test "x$EMSCRIPTEN" != "x"],[
  enable_asm="no"
  AC_MSG_WARN([compiling to javascript - asm implementations disabled])
])

AC_ARG_ENABLE(pie,
[AS_HELP_STRING(--disable-pie,Do not produce position independent executables)],
 enable_pie=$enableval, enable_pie="maybe")

AS_CASE([$host_os], [mingw*|cygwin*|msys], [enable_pie="no"])

AC_ARG_ENABLE(blocking-random,
[AS_HELP_STRING(--enable-blocking-random,Enable this switch only if /dev/urandom is totally broken on the target platform)],
[
  AS_IF([test "x$enableval" = "xyes"], [
    AC_DEFINE([USE_BLOCKING_RANDOM], [1], [/dev/urandom is insecure on the target platform])
  ])
])

AC_ARG_ENABLE(minimal,
[AS_HELP_STRING(--enable-minimal,
  [Only compile the minimum set of functions required for the high-level API])],
[
  AS_IF([test "x$enableval" = "xyes"], [
    enable_minimal="yes"
  ], [
    enable_minimal="no"
  ])
],
[
  enable_minimal="no"
])
AM_CONDITIONAL([MINIMAL], [test x$enable_minimal = xyes])

AC_ARG_WITH(safecode,
[AS_HELP_STRING(--with-safecode,For maintainers only - please do not use)],
[AS_IF([test "x$withval" = "xyes"], [
    AC_ARG_VAR([SAFECODE_HOME], [set to the safecode base directory])
    : ${SAFECODE_HOME:=/opt/safecode}
    LDFLAGS="$LDFLAGS -L${SAFECODE_HOME}/lib"
    LIBS="$LIBS -lsc_dbg_rt -lpoolalloc_bitmap -lstdc++"
    CFLAGS="$CFLAGS -fmemsafety"
  ])
])

AC_ARG_ENABLE(debug,
[AS_HELP_STRING(--enable-debug,For maintainers only - please do not use)],
[
  AS_IF([test "x$enableval" = "xyes"], [
    AS_IF([test "x$LX_CFLAGS" = "xNONE"], [
      nxflags=""
      for flag in `echo $CFLAGS`; do
        AS_CASE([$flag],
          [-O*], [ ],
          [-g*], [ ],
          [*], [AS_VAR_APPEND([nxflags], [" $flag"])])
      done
      CFLAGS="$nxflags -O0 -g3"
    ])
    CPPFLAGS="$CPPFLAGS -DDEBUG=1"
  ])
])

AC_ARG_ENABLE(opt,
[AS_HELP_STRING(--enable-opt,Optimize for the native CPU - The resulting library will be faster but not portable)],
[
  AS_IF([test "x$enableval" = "xyes"], [
    CFLAGS="$CFLAGS -flto -march=native"
    LDFLAGS="$LDFLAGS -flto -march=native"])
])

AC_SUBST([MAINT])

dnl Checks

AC_PROG_CC_C99
AM_PROG_AS
AC_USE_SYSTEM_EXTENSIONS

AC_CHECK_DEFINE([__native_client__], [NATIVECLIENT="yes"], [])

AC_CHECK_DEFINE([_FORTIFY_SOURCE], [], [
  AX_CHECK_COMPILE_FLAG([-D_FORTIFY_SOURCE=2],
    [CPPFLAGS="$CPPFLAGS -D_FORTIFY_SOURCE=2"])
])

AX_CHECK_COMPILE_FLAG([-fvisibility=hidden],
  [CFLAGS="$CFLAGS -fvisibility=hidden"])

AS_CASE([$host_os], [cygwin*|mingw*|msys|pw32*|cegcc*], [ ], [
  AX_CHECK_COMPILE_FLAG([-fPIC], [
    AX_CHECK_LINK_FLAG([-fPIC],
      [CFLAGS="$CFLAGS -fPIC"]
    )
  ])
])

AS_IF([test "$enable_pie" != "no"],[
  AX_CHECK_COMPILE_FLAG([-fPIE], [
    AX_CHECK_LINK_FLAG([-fPIE],
      [AX_CHECK_LINK_FLAG([-pie],
        [CFLAGS="$CFLAGS -fPIE"
         LDFLAGS="$LDFLAGS -pie"])
    ])
  ])
])

AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing], [CFLAGS="$CFLAGS -fno-strict-aliasing"])
AX_CHECK_COMPILE_FLAG([-fno-strict-overflow], [CFLAGS="$CFLAGS -fno-strict-overflow"], [
  AX_CHECK_COMPILE_FLAG([-fwrapv], [CFLAGS="$CFLAGS -fwrapv"])
])

LIBTOOL_OLD_FLAGS="$LIBTOOL_EXTRA_FLAGS"
LIBTOOL_EXTRA_FLAGS="$LIBTOOL_EXTRA_FLAGS -version-info $SODIUM_LIBRARY_VERSION"
AC_ARG_ENABLE(soname-versions,
  [AC_HELP_STRING([--enable-soname-versions], [enable soname versions (must be disabled for Android) (default: enabled)])],
    [
        AS_IF([test "x$enableval" = "xno"], [
          LIBTOOL_EXTRA_FLAGS="$LIBTOOL_OLD_FLAGS -avoid-version"
        ])
    ]
)

AS_CASE([$host_os],
  [cygwin*|mingw*|msys|pw32*|cegcc*], [
    AX_CHECK_LINK_FLAG([-Wl,--dynamicbase], [LDFLAGS="$LDFLAGS -Wl,--dynamicbase"])
    AX_CHECK_LINK_FLAG([-Wl,--nxcompat], [LDFLAGS="$LDFLAGS -Wl,--nxcompat"])
  ])

AS_IF([test "x$enable_ssp" != "xno"],[

AS_CASE([$host_os],
  [cygwin*|mingw*|msys|pw32*|cegcc*|*aix*|*sunos*|*solaris*], [ ],
  [*], [
    AX_CHECK_COMPILE_FLAG([-fstack-protector], [
      AX_CHECK_LINK_FLAG([-fstack-protector],
        [CFLAGS="$CFLAGS -fstack-protector"]
      )
    ])
  ])
])

AX_CHECK_COMPILE_FLAG([-Winit-self], [CFLAGS="$CFLAGS -Winit-self"])
AX_CHECK_COMPILE_FLAG([-Wwrite-strings], [CFLAGS="$CFLAGS -Wwrite-strings"])
AX_CHECK_COMPILE_FLAG([-Wdiv-by-zero], [CFLAGS="$CFLAGS -Wdiv-by-zero"])
AX_CHECK_COMPILE_FLAG([-Wsometimes-uninitialized], [CFLAGS="$CFLAGS -Wsometimes-uninitialized"])

AC_ARG_VAR([CWFLAGS], [define to compilation flags for generating extra warnings])

AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wall], [CWFLAGS="$CWFLAGS -Wall"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wextra], [CWFLAGS="$CWFLAGS -Wextra"])

AC_MSG_CHECKING(for clang)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[
#ifndef __clang__
be sad
#endif
]])],
  [AC_MSG_RESULT(yes)
   AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wno-unknown-warning-option],
     [CWFLAGS="$CWFLAGS -Wno-unknown-warning-option"])
  ],
  [AC_MSG_RESULT(no)
])

AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wbad-function-cast], [CWFLAGS="$CWFLAGS -Wbad-function-cast"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wcast-align], [CWFLAGS="$CWFLAGS -Wcast-align"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wcast-qual], [CWFLAGS="$CWFLAGS -Wcast-qual"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wchar-subscripts], [CWFLAGS="$CWFLAGS -Wchar-subscripts"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wcomment], [CWFLAGS="$CWFLAGS -Wcomment"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wfloat-equal], [CWFLAGS="$CWFLAGS -Wfloat-equal"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wformat=2], [CWFLAGS="$CWFLAGS -Wformat=2"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wimplicit], [CWFLAGS="$CWFLAGS -Wimplicit"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wmissing-declarations], [CWFLAGS="$CWFLAGS -Wmissing-declarations"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wmissing-prototypes], [CWFLAGS="$CWFLAGS -Wmissing-prototypes"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wnormalized=id], [CWFLAGS="$CWFLAGS -Wnormalized=id"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Woverride-init], [CWFLAGS="$CWFLAGS -Woverride-init"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wparentheses], [CWFLAGS="$CWFLAGS -Wparentheses"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wpointer-arith], [CWFLAGS="$CWFLAGS -Wpointer-arith"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wredundant-decls], [CWFLAGS="$CWFLAGS -Wredundant-decls"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wstrict-prototypes], [CWFLAGS="$CWFLAGS -Wstrict-prototypes"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wswitch-enum], [CWFLAGS="$CWFLAGS -Wswitch-enum"])
AX_CHECK_COMPILE_FLAG([$CWFLAGS -Wvariable-decl], [CWFLAGS="$CWFLAGS -Wvariable-decl"])

AX_CHECK_LINK_FLAG([-Wl,-z,relro], [LDFLAGS="$LDFLAGS -Wl,-z,relro"])
AX_CHECK_LINK_FLAG([-Wl,-z,now], [LDFLAGS="$LDFLAGS -Wl,-z,now"])
AX_CHECK_LINK_FLAG([-Wl,-z,noexecstack], [LDFLAGS="$LDFLAGS -Wl,-z,noexecstack"])

LT_INIT
AC_SUBST(LIBTOOL_DEPS)

AC_ARG_VAR([AR], [path to the ar utility])
AC_CHECK_TOOL([AR], [ar], [ar])

dnl Checks for headers

AS_IF([test "x$EMSCRIPTEN" = "x"],[

  AC_MSG_CHECKING(for MMX instructions set)
  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-mmmx], [CFLAGS="$CFLAGS -mmmx"])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("mmx")
#include <mmintrin.h>
]], [[ __m64 x = _mm_setzero_si64(); ]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_MMINTRIN_H], [1], [mmx is available])
     AX_CHECK_COMPILE_FLAG([-mmmx], [CFLAGS_MMX="-mmmx"])],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

  AC_MSG_CHECKING(for SSE2 instructions set)
  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-msse2], [CFLAGS="$CFLAGS -msse2"])
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("sse2")
#ifndef __SSE2__
# define __SSE2__
#endif
#include <emmintrin.h>
]], [[ __m128d x = _mm_setzero_pd(); ]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_EMMINTRIN_H], [1], [sse2 is available])
     AX_CHECK_COMPILE_FLAG([-msse2], [CFLAGS_SSE2="-msse2"])],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-msse3], [CFLAGS="$CFLAGS -msse3"])
  AC_MSG_CHECKING(for SSE3 instructions set)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("sse3")
#include <pmmintrin.h>
]], [[ __m128 x = _mm_addsub_ps(_mm_cvtpd_ps(_mm_setzero_pd()),
                                _mm_cvtpd_ps(_mm_setzero_pd())); ]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_PMMINTRIN_H], [1], [sse3 is available])
     AX_CHECK_COMPILE_FLAG([-msse3], [CFLAGS_SSE3="-msse3"])],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-mssse3], [CFLAGS="$CFLAGS -mssse3"])
  AC_MSG_CHECKING(for SSSE3 instructions set)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("ssse3")
#include <tmmintrin.h>
]], [[ __m64 x = _mm_abs_pi32(_m_from_int(0)); ]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_TMMINTRIN_H], [1], [ssse3 is available])
     AX_CHECK_COMPILE_FLAG([-mssse3], [CFLAGS_SSSE3="-mssse3"])],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-msse4.1], [CFLAGS="$CFLAGS -msse4.1"])
  AC_MSG_CHECKING(for SSE4.1 instructions set)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("sse4.1")
#include <smmintrin.h>
]], [[ __m128i x = _mm_minpos_epu16(_mm_setzero_si128()); ]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_SMMINTRIN_H], [1], [sse4.1 is available])
     AX_CHECK_COMPILE_FLAG([-msse4.1], [CFLAGS_SSE41="-msse4.1"])],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-mavx], [CFLAGS="$CFLAGS -mavx"])
  AC_MSG_CHECKING(for AVX instructions set)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("avx")
#include <immintrin.h>
]], [[ _mm256_zeroall(); ]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_AVXINTRIN_H], [1], [AVX is available])
     AX_CHECK_COMPILE_FLAG([-mavx], [CFLAGS_AVX="-mavx"])],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

  oldcflags="$CFLAGS"
  AX_CHECK_COMPILE_FLAG([-maes], [CFLAGS="$CFLAGS -maes"])
  AX_CHECK_COMPILE_FLAG([-mpclmul], [CFLAGS="$CFLAGS -mpclmul"])
  AC_MSG_CHECKING(for AESNI instructions set and PCLMULQDQ)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC target("aes")
#pragma GCC target("pclmul")
#include <wmmintrin.h>
]], [[ __m128i x = _mm_aesimc_si128(_mm_setzero_si128());
       __m128i y = _mm_clmulepi64_si128(_mm_setzero_si128(), _mm_setzero_si128(), 0);]])],
    [AC_MSG_RESULT(yes)
     AC_DEFINE([HAVE_WMMINTRIN_H], [1], [aesni is available])
     AX_CHECK_COMPILE_FLAG([-maes], [CFLAGS_AESNI="-maes"])
     AX_CHECK_COMPILE_FLAG([-mpclmul], [CFLAGS_PCLMUL="-mpclmul"])
     ],
    [AC_MSG_RESULT(no)])
  CFLAGS="$oldcflags"

])

AC_SUBST(CFLAGS_MMX)
AC_SUBST(CFLAGS_SSE2)
AC_SUBST(CFLAGS_SSE3)
AC_SUBST(CFLAGS_SSSE3)
AC_SUBST(CFLAGS_SSE41)
AC_SUBST(CFLAGS_AESNI)
AC_SUBST(CFLAGS_PCLMUL)

AC_CHECK_HEADERS([sys/mman.h])

dnl Checks for typedefs, structures, and compiler characteristics.

AC_C_INLINE
AC_C_BIGENDIAN(
  AC_DEFINE(NATIVE_BIG_ENDIAN, 1, [machine is bigendian]),
  AC_DEFINE(NATIVE_LITTLE_ENDIAN, 1, [machine is littleendian]),
  AC_MSG_ERROR([unknown endianess]),
  AC_MSG_ERROR([universal endianess is not supported - compile separately and use lipo(1)])
)

AC_MSG_CHECKING(whether __STDC_LIMIT_MACROS is required)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <limits.h>
#include <stdint.h>
]], [[
(void) SIZE_MAX;
(void) UINT64_MAX;
]])],
  [AC_MSG_RESULT(no)],
  [AC_MSG_RESULT(yes)
   CPPFLAGS="$CPPFLAGS -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS"
])

HAVE_AMD64_ASM_V=0
AS_IF([test "$enable_asm" != "no"],[
  AC_MSG_CHECKING(whether we can use x86_64 asm code)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  ]], [[
#if defined(__amd64) || defined(__amd64__) || defined(__x86_64__)
# if defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_WIN32) || defined(_WIN64)
#  error Windows x86_64 calling conventions are not supported yet
# endif
/* neat */
#else
# error !x86_64
#endif
unsigned char i = 0, o = 0, t;
__asm__ __volatile__ ("pxor %%xmm12, %%xmm6 \n"
                      "movb (%[i]), %[t] \n"
                      "addb %[t], (%[o]) \n"
                      : [t] "=&r"(t)
                      : [o] "D"(&o), [i] "S"(&i)
                      : "memory", "flags", "cc");
]])],
  [AC_MSG_RESULT(yes)
   AC_DEFINE([HAVE_AMD64_ASM], [1], [x86_64 asm code can be used])
   HAVE_AMD64_ASM_V=1],
  [AC_MSG_RESULT(no)])
])
AM_CONDITIONAL([HAVE_AMD64_ASM], [test $HAVE_AMD64_ASM_V = 1])
AC_SUBST(HAVE_AMD64_ASM_V)

HAVE_AVX_ASM_V=0
AS_IF([test "$enable_asm" != "no"],[
  AC_MSG_CHECKING(whether we can assemble AVX opcodes)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
  ]], [[
#if defined(__amd64) || defined(__amd64__) || defined(__x86_64__)
# if defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_WIN32) || defined(_WIN64)
#  error Windows x86_64 calling conventions are not supported yet
# endif
/* neat */
#else
# error !x86_64
#endif
__asm__ __volatile__ ("vpunpcklqdq %xmm0,%xmm13,%xmm0");
]])],
  [AC_MSG_RESULT(yes)
   AC_DEFINE([HAVE_AVX_ASM], [1], [AVX opcodes are supported])
   HAVE_AVX_ASM_V=1],
  [AC_MSG_RESULT(no)])
])
AM_CONDITIONAL([HAVE_AVX_ASM], [test $HAVE_AVX_ASM_V = 1])
AC_SUBST(HAVE_AVX_ASM_V)

AC_MSG_CHECKING(for 128-bit arithmetic)
HAVE_TI_MODE_V=0
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if !defined(__GNUC__) && !defined(__SIZEOF_INT128__)
# error mode(TI) is a gcc extension, and __int128 is not available
#endif
#if defined(__clang__) && !defined(__x86_64__)
# error clang does not properly handle the 128-bit type on 32-bit systems
#endif
#ifndef NATIVE_LITTLE_ENDIAN
# error libsodium currently expects a little endian CPU for the 128-bit type
#endif
#ifdef __EMSCRIPTEN__
# error emscripten currently supports only shift operations on integers \
#       larger than 64 bits
#endif
#include <stddef.h>
#include <stdint.h>
#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
#else
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif
void fcontract(uint128_t *t) {
  *t += 0x8000000000000 - 1;
}
]], [[
(void) fcontract;
]])],
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_TI_MODE], [1], [gcc TI mode is available])
 HAVE_TI_MODE_V=1],
[AC_MSG_RESULT(no)])
AM_CONDITIONAL([HAVE_TI_MODE], [test $HAVE_TI_MODE_V = 1])
AC_SUBST(HAVE_TI_MODE_V)

HAVE_CPUID_V=0
AS_IF([test "$enable_asm" != "no"],[
  AC_MSG_CHECKING(for cpuid instruction)
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ ]], [[
unsigned int cpu_info[4];
__asm__ __volatile__ ("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1" :
                      "=a" (cpu_info[0]), "=&r" (cpu_info[1]),
                      "=c" (cpu_info[2]), "=d" (cpu_info[3]) :
                      "0" (0U), "2" (0U));
  ]])],
  [AC_MSG_RESULT(yes)
   AC_DEFINE([HAVE_CPUID], [1], [cpuid instruction is available])
   HAVE_CPUID_V=1],
  [AC_MSG_RESULT(no)])
  ])
AC_SUBST(HAVE_CPUID_V)

AC_MSG_CHECKING(if weak symbols are supported)
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
__attribute__((weak)) void __dummy(void *x) { }
void f(void *x) { __dummy(x); }
]], [[ ]]
)],
[AC_MSG_RESULT(yes)
 AC_DEFINE([HAVE_WEAK_SYMBOLS], [1], [weak symbols are supported])],
[AC_MSG_RESULT(no)])

AC_MSG_CHECKING(if data alignment is required)
aligned_access_required=yes
AS_CASE([$host_cpu],
  [i*86 | x86_64 | powerpc* | s390*],
    [aligned_access_required=no],
  [arm*],
    [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifndef __ARM_FEATURE_UNALIGNED
# error data alignment is required
#endif
      ]], [[]])], [aligned_access_required=no], [])]
)
AS_IF([test "x$aligned_access_required" = "xyes"],
  [AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)
   AC_DEFINE([CPU_UNALIGNED_ACCESS], [1], [unaligned memory access is supported])])

dnl Checks for functions and headers

AS_IF([test "x$EMSCRIPTEN" = "x"],[
  AC_CHECK_FUNCS([arc4random arc4random_buf])
  AC_CHECK_FUNCS([mmap mlock madvise mprotect explicit_bzero])
])
AC_CHECK_FUNCS([posix_memalign getpid])

AC_SUBST([LIBTOOL_EXTRA_FLAGS])

TEST_LDFLAGS=''
AS_IF([test "x$EMSCRIPTEN" != "x"],[
  EXEEXT=.js
  TEST_LDFLAGS='--memory-init-file 0 --pre-js pre.js.inc -s NO_BROWSER=1 -s RESERVED_FUNCTION_POINTERS=8'
])
AC_SUBST(TEST_LDFLAGS)
AM_CONDITIONAL([EMSCRIPTEN], [test "x$EMSCRIPTEN" != "x"])

AM_CONDITIONAL([NATIVECLIENT], [test "x$NATIVECLIENT" != "x"])

dnl Libtool.

LT_INIT([dlopen])
AC_LIBTOOL_WIN32_DLL
gl_LD_OUTPUT_DEF

dnl Output.

AH_VERBATIM([NDEBUG], [/* Always evaluate assert() calls */
#ifdef NDEBUG
#/**/undef/**/ NDEBUG
#endif])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/libsodium/Makefile
                 src/libsodium/include/Makefile
                 src/libsodium/include/sodium/version.h
                 ])
AC_OUTPUT
