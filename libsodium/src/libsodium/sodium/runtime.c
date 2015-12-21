
#ifdef HAVE_ANDROID_GETCPUFEATURES
# include <cpu-features.h>
#endif

#include "runtime.h"

typedef struct CPUFeatures_ {
    int initialized;
    int has_neon;
    int has_sse2;
    int has_sse3;
    int has_ssse3;
    int has_sse41;
    int has_avx;
    int has_pclmul;
    int has_aesni;
} CPUFeatures;

static CPUFeatures _cpu_features;

#define CPUID_SSE2      0x04000000
#define CPUIDECX_SSE3   0x00000001
#define CPUIDECX_SSSE3  0x00000200
#define CPUIDECX_SSE41  0x00080000
#define CPUIDECX_AVX    0x10000000
#define CPUIDECX_PCLMUL 0x00000002
#define CPUIDECX_AESNI  0x02000000

static int
_sodium_runtime_arm_cpu_features(CPUFeatures * const cpu_features)
{
#ifndef __arm__
    cpu_features->has_neon = 0;
    return -1;
#else
# ifdef __APPLE__
#  ifdef __ARM_NEON__
    cpu_features->has_neon = 1;
#  else
    cpu_features->has_neon = 0;
#  endif
# elif defined(HAVE_ANDROID_GETCPUFEATURES) && defined(ANDROID_CPU_ARM_FEATURE_NEON)
    cpu_features->has_neon =
        (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0x0;
# else
    cpu_features->has_neon = 0;
# endif
    return 0;
#endif
}

static void
_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type)
{
#if defined(_MSC_VER) && \
    (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86))
    __cpuid((int *) cpu_info, cpu_info_type);
#elif defined(HAVE_CPUID)
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
# ifdef __i386__
    __asm__ __volatile__ ("pushfl; pushfl; "
                          "popl %0; "
                          "movl %0, %1; xorl %2, %0; "
                          "pushl %0; "
                          "popfl; pushfl; popl %0; popfl" :
                          "=&r" (cpu_info[0]), "=&r" (cpu_info[1]) :
                          "i" (0x200000));
    if (((cpu_info[0] ^ cpu_info[1]) & 0x200000) == 0x0) {
        return; /* LCOV_EXCL_LINE */
    }
# endif
# ifdef __i386__
    __asm__ __volatile__ ("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1" :
                          "=a" (cpu_info[0]), "=&r" (cpu_info[1]),
                          "=c" (cpu_info[2]), "=d" (cpu_info[3]) :
                          "0" (cpu_info_type), "2" (0U));
# elif defined(__x86_64__)
    __asm__ __volatile__ ("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1" :
                          "=a" (cpu_info[0]), "=&r" (cpu_info[1]),
                          "=c" (cpu_info[2]), "=d" (cpu_info[3]) :
                          "0" (cpu_info_type), "2" (0U));
# else
    __asm__ __volatile__ ("cpuid" :
                          "=a" (cpu_info[0]), "=b" (cpu_info[1]),
                          "=c" (cpu_info[2]), "=d" (cpu_info[3]) :
                          "0" (cpu_info_type), "2" (0U));
# endif
#else
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
#endif
}

static int
_sodium_runtime_intel_cpu_features(CPUFeatures * const cpu_features)
{
    unsigned int cpu_info[4];
    unsigned int id;

    _cpuid(cpu_info, 0x0);
    if ((id = cpu_info[0]) == 0U) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _cpuid(cpu_info, 0x00000001);
#if defined(HAVE_EMMINTRIN_H) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
    cpu_features->has_sse2 = ((cpu_info[3] & CPUID_SSE2) != 0x0);
#else
    cpu_features->has_sse2 = 0;
#endif

#if defined(HAVE_PMMINTRIN_H) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
    cpu_features->has_sse3 = ((cpu_info[2] & CPUIDECX_SSE3) != 0x0);
#else
    cpu_features->has_sse3 = 0;
#endif

#if defined(HAVE_TMMINTRIN_H) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
    cpu_features->has_ssse3 = ((cpu_info[2] & CPUIDECX_SSSE3) != 0x0);
#else
    cpu_features->has_ssse3 = 0;
#endif

#if defined(HAVE_SMMINTRIN_H) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
    cpu_features->has_sse41 = ((cpu_info[2] & CPUIDECX_SSE41) != 0x0);
#else
    cpu_features->has_sse41 = 0;
#endif

#if defined(HAVE_AVXINTRIN_H) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
    cpu_features->has_avx = ((cpu_info[2] & CPUIDECX_AVX) != 0x0);
#else
    cpu_features->has_avx = 0;
#endif

#if defined(HAVE_WMMINTRIN_H) || \
    (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_AMD64) || defined(_M_IX86)))
    cpu_features->has_pclmul = ((cpu_info[2] & CPUIDECX_PCLMUL) != 0x0);
    cpu_features->has_aesni = ((cpu_info[2] & CPUIDECX_AESNI) != 0x0);
#else
    cpu_features->has_pclmul = 0;
    cpu_features->has_aesni = 0;
#endif

    return 0;
}

int
_sodium_runtime_get_cpu_features(void)
{
    int ret = -1;

    ret &= _sodium_runtime_arm_cpu_features(&_cpu_features);
    ret &= _sodium_runtime_intel_cpu_features(&_cpu_features);
    _cpu_features.initialized = 1;

    return ret;
}

int
sodium_runtime_has_neon(void) {
    return _cpu_features.has_neon;
}

int
sodium_runtime_has_sse2(void) {
    return _cpu_features.has_sse2;
}

int
sodium_runtime_has_sse3(void) {
    return _cpu_features.has_sse3;
}

int
sodium_runtime_has_ssse3(void) {
    return _cpu_features.has_ssse3;
}

int
sodium_runtime_has_sse41(void) {
    return _cpu_features.has_sse41;
}

int
sodium_runtime_has_avx(void) {
    return _cpu_features.has_avx;
}

int
sodium_runtime_has_pclmul(void) {
    return _cpu_features.has_pclmul;
}

int
sodium_runtime_has_aesni(void) {
    return _cpu_features.has_aesni;
}
