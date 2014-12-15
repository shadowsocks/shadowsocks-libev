#ifndef __STDC_WANT_LIB_EXT1__
# define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif

#include "utils.h"
#include "randombytes.h"
#ifdef _WIN32
# include <windows.h>
# include <wincrypt.h>
#ifdef __MINGW32__
#ifndef SecureZeroMemory
#define SecureZeroMemory(p,s) RtlFillMemory((p),(s),0)
#endif
#endif
#else
# include <unistd.h>
#endif

#define CANARY_SIZE 16U
#define GARBAGE_VALUE 0xd0

#ifndef MAP_NOCORE
# define MAP_NOCORE 0
#endif
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
# define MAP_ANON MAP_ANONYMOUS
#endif
#if defined(_WIN32) || defined(MAP_ANON) || defined(HAVE_POSIX_MEMALIGN)
# define HAVE_ALIGNED_MALLOC
#endif
#if defined(HAVE_MPROTECT) && !(defined(PROT_NONE) && defined(PROT_READ) && defined(PROT_WRITE))
# undef HAVE_MPROTECT
#endif
#if defined(HAVE_ALIGNED_MALLOC) && (defined(_WIN32) || defined(HAVE_MPROTECT))
# define HAVE_PAGE_PROTECTION
#endif

static size_t page_size;
static unsigned char canary[CANARY_SIZE];

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_sodium_dummy_symbol_to_prevent_lto(void * const pnt, const size_t len)
{
    (void) pnt;
    (void) len;
}
#endif

void
sodium_memzero(void * const pnt, const size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(pnt, len);
#elif defined(HAVE_MEMSET_S)
    if (memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
        abort(); /* LCOV_EXCL_LINE */
    }
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(pnt, len);
#elif HAVE_WEAK_SYMBOLS
    memset(pnt, 0, len);
    _sodium_dummy_symbol_to_prevent_lto(pnt, len);
#else
    volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
    size_t                     i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}

int
sodium_memcmp(const void * const b1_, const void * const b2_, size_t len)
{
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
    size_t               i;
    unsigned char        d = (unsigned char) 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (int) ((1 & ((d - 1) >> 8)) - 1);
}

/* Derived from original code by CodesInChaos */
char *
sodium_bin2hex(char * const hex, const size_t hex_maxlen,
               const unsigned char * const bin, const size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    if (bin_len >= SIZE_MAX / 2 || hex_maxlen < bin_len * 2U) {
        abort(); /* LCOV_EXCL_LINE */
    }
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87 + c + (((c - 10) >> 31) & -39)) << 8 |
            (unsigned char) (87 + b + (((b - 10) >> 31) & -39));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    hex[i * 2U] = 0;

    return hex;
}

int
sodium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
               const char * const hex, const size_t hex_len,
               const char * const ignore, size_t * const bin_len,
               const char ** const hex_end)
{
    size_t        bin_pos = (size_t) 0U;
    size_t        hex_pos = (size_t) 0U;
    int           ret = 0;
    unsigned char c;
    unsigned char c_acc = 0U;
    unsigned char c_num;
    unsigned char c_val;
    unsigned char state = 0U;

    while (hex_pos < hex_len) {
        c = (unsigned char) hex[hex_pos];
        if ((c_num = c ^ 48U) < 10U) {
            c_val = c_num;
        } else if ((c_num = (c & ~32U)) > 64 && c_num < 71U) {
            c_val = c_num - 55U;
        } else if (ignore != NULL && strchr(ignore, c) != NULL && state == 0U) {
            hex_pos++;
            continue;
        } else {
            break;
        }
        if (bin_pos >= bin_maxlen) {
            ret = -1;
            errno = ERANGE;
            break;
        }
        if (state == 0U) {
            c_acc = c_val * 16U;
        } else {
            bin[bin_pos++] = c_acc | c_val;
        }
        state = ~state;
        hex_pos++;
    }
    if (state != 0U) {
        hex_pos--;
    }
    if (hex_end != NULL) {
        *hex_end = &hex[hex_pos];
    }
    if (bin_len != NULL) {
        *bin_len = bin_pos;
    }
    return ret;
}

int
sodium_mlock(void * const addr, const size_t len)
{
#ifdef MADV_DONTDUMP
    (void) madvise(addr, len, MADV_DONTDUMP);
#endif
#ifdef HAVE_MLOCK
    return mlock(addr, len);
#elif defined(_WIN32)
    return -(VirtualLock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int
sodium_munlock(void * const addr, const size_t len)
{
    sodium_memzero(addr, len);
#ifdef MADV_DODUMP
    (void) madvise(addr, len, MADV_DODUMP);
#endif
#ifdef HAVE_MLOCK
    return munlock(addr, len);
#elif defined(_WIN32)
    return -(VirtualUnlock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int
_sodium_alloc_init(void)
{
#if defined(_SC_PAGESIZE)
    long page_size_ = sysconf(_SC_PAGESIZE);
    if (page_size_ > 0L) {
        page_size = (size_t) page_size_;
    }
#elif defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_size = (size_t) si.dwPageSize;
#endif
    if (page_size < CANARY_SIZE) {
        abort(); /* LCOV_EXCL_LINE */
    }
    randombytes_buf(canary, sizeof canary);

    return 0;
}

static inline size_t
_page_round(const size_t size)
{
    const size_t page_mask = page_size - 1U;

    return (size + page_mask) & ~page_mask;
}

static int
_mprotect_noaccess(void *ptr, size_t size)
{
#if defined(HAVE_MPROTECT) && defined(HAVE_PAGE_PROTECTION)
    return mprotect(ptr, size, PROT_NONE);
#elif defined(_WIN32)
    {
        DWORD old;
        return -(VirtualProtect(ptr, size, PAGE_NOACCESS, &old) == 0);
    }
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_readonly(void *ptr, size_t size)
{
#if defined(HAVE_MPROTECT) && defined(HAVE_PAGE_PROTECTION)
    return mprotect(ptr, size, PROT_READ);
#elif defined(_WIN32)
    {
        DWORD old;
        return -(VirtualProtect(ptr, size, PAGE_READONLY, &old) == 0);
    }
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_readwrite(void *ptr, size_t size)
{
#if defined(HAVE_MPROTECT) && defined(HAVE_PAGE_PROTECTION)
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
#elif defined(_WIN32)
    {
        DWORD old;
        return -(VirtualProtect(ptr, size, PAGE_READWRITE, &old) == 0);
    }
#else
    errno = ENOSYS;
    return -1;
#endif
}

static void
_out_of_bounds(void)
{
#ifdef SIGSEGV
    raise(SIGSEGV);
#elif defined(SIGKILL)
    raise(SIGKILL);
#endif
    abort();
}  /* LCOV_EXCL_LINE */

static __attribute__((malloc)) unsigned char *
_alloc_aligned(const size_t size)
{
    void *ptr;

#ifdef MAP_ANON
    if ((ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) == MAP_FAILED) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    } /* LCOV_EXCL_LINE */
#elif defined(HAVE_POSIX_MEMALIGN)
    if (posix_memalign(&ptr, page_size, size) != 0) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    } /* LCOV_EXCL_LINE */
#elif defined(_WIN32)
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#elif !defined(HAVE_ALIGNED_MALLOC)
    ptr = malloc(size);
#else
# error Bug
#endif
    return (unsigned char *) ptr;
}

static void
_free_aligned(unsigned char * const ptr, const size_t size)
{
#ifdef MAP_ANON
    (void) munmap(ptr, size);
#elif defined(HAVE_POSIX_MEMALIGN)
    free(ptr);
#elif defined(_WIN32)
    VirtualFree(ptr, 0U, MEM_RELEASE);
#else
    free(ptr);
#endif
}

static unsigned char *
_unprotected_ptr_from_user_ptr(const void *ptr)
{
    uintptr_t      unprotected_ptr_u;
    unsigned char *canary_ptr;
    size_t         page_mask;

    canary_ptr = ((unsigned char *) ptr) - sizeof canary;
    page_mask = page_size - 1U;
    unprotected_ptr_u = ((uintptr_t) canary_ptr & (uintptr_t) ~page_mask);
    if (unprotected_ptr_u <= page_size * 2U) {
        abort(); /* LCOV_EXCL_LINE */
    }
    return (unsigned char *) unprotected_ptr_u;
}

static __attribute__((malloc)) void *
_sodium_malloc(const size_t size)
{
    void          *user_ptr;
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         size_with_canary;
    size_t         total_size;
    size_t         unprotected_size;

    if (size >= (size_t) SIZE_MAX - page_size * 4U) {
        errno = ENOMEM;
        return NULL;
    }
    if (page_size <= sizeof canary || page_size < sizeof unprotected_size) {
        abort(); /* LCOV_EXCL_LINE */
    }
    size_with_canary = (sizeof canary) + size;
    unprotected_size = _page_round(size_with_canary);
    total_size = page_size + page_size + unprotected_size + page_size;
    if ((base_ptr = _alloc_aligned(total_size)) == NULL) {
        return NULL; /* LCOV_EXCL_LINE */
    }
    unprotected_ptr = base_ptr + page_size * 2U;
    _mprotect_noaccess(base_ptr + page_size, page_size);
#ifndef HAVE_PAGE_PROTECTION
    memcpy(unprotected_ptr + unprotected_size, canary, sizeof canary);
#endif
    _mprotect_noaccess(unprotected_ptr + unprotected_size, page_size);
    sodium_mlock(unprotected_ptr, unprotected_size);
    canary_ptr = unprotected_ptr + _page_round(size_with_canary) -
        size_with_canary;
    user_ptr = canary_ptr + sizeof canary;
    memcpy(canary_ptr, canary, sizeof canary);
    memcpy(base_ptr, &unprotected_size, sizeof unprotected_size);
    _mprotect_readonly(base_ptr, page_size);
    assert(_unprotected_ptr_from_user_ptr(user_ptr) == unprotected_ptr);

    return user_ptr;
}

__attribute__((malloc)) void *
sodium_malloc(const size_t size)
{
    void *ptr;

    if ((ptr = _sodium_malloc(size)) == NULL) {
        return NULL; /* LCOV_EXCL_LINE */
    }
    memset(ptr, (int) GARBAGE_VALUE, size);

    return ptr;
}

__attribute__((malloc)) void *
sodium_allocarray(size_t count, size_t size)
{
    size_t total_size;

    if (size >= (size_t) SIZE_MAX / count) {
        errno = ENOMEM;
        return NULL;
    }
    total_size = count * size;

    return sodium_malloc(total_size);
}

void
sodium_free(void *ptr)
{
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         total_size;
    size_t         unprotected_size;

    if (ptr == NULL) {
        return;
    }
    canary_ptr = ((unsigned char *) ptr) - sizeof canary;
    if (sodium_memcmp(canary_ptr, canary, sizeof canary) != 0) {
        _out_of_bounds();
    }
    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr = unprotected_ptr - page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);
    total_size = page_size + page_size + unprotected_size + page_size;
    _mprotect_readwrite(base_ptr, total_size);
#ifndef HAVE_PAGE_PROTECTION
    if (sodium_memcmp(unprotected_ptr + unprotected_size,
                      canary, sizeof canary) != 0) {
        _out_of_bounds();
    }
#endif
    sodium_munlock(unprotected_ptr, unprotected_size);
    _free_aligned(base_ptr, total_size);
}

static int
_sodium_mprotect(void *ptr, int (*cb)(void *ptr, size_t size))
{
    unsigned char *base_ptr;
    unsigned char *unprotected_ptr;
    size_t         unprotected_size;

    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr = unprotected_ptr - page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);

    return cb(unprotected_ptr, unprotected_size);
}

int
sodium_mprotect_noaccess(void *ptr)
{
    return _sodium_mprotect(ptr, _mprotect_noaccess);
}

int
sodium_mprotect_readonly(void *ptr)
{
    return _sodium_mprotect(ptr, _mprotect_readonly);
}

int
sodium_mprotect_readwrite(void *ptr)
{
    return _sodium_mprotect(ptr, _mprotect_readwrite);
}
