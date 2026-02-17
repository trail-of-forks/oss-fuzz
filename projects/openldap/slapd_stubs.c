/*
 * slapd_stubs.c — Linker stubs for slapd fuzzing harnesses
 *
 * Provides:
 * 1. --wrap stubs for determinism (sleep, nanosleep, gettimeofday)
 * 2. Missing symbols from main.c that slapd code references
 *
 * These allow linking slapd object files without main.o and without
 * modifying any OpenLDAP source code.
 */

#include <time.h>
#include <sys/time.h>

/* === --wrap stubs for determinism and no blocking === */

unsigned int __wrap_sleep(unsigned int s) {
    (void)s;
    return 0;
}

int __wrap_nanosleep(const struct timespec *req, struct timespec *rem) {
    (void)req;
    (void)rem;
    return 0;
}

int __wrap_gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    if (tv) {
        tv->tv_sec = 1000000;
        tv->tv_usec = 0;
    }
    return 0;
}

/* Thread pool TID stub — in normal slapd, each pool worker thread
 * has a thread-local context with its ID. The fuzzer runs single-threaded
 * on the main thread which has no pool context, causing a NULL deref.
 * Return a fixed TID of 0 for the single fuzzer thread. */
int __wrap_ldap_pvt_thread_pool_tid(void *pool) {
    (void)pool;
    return 0;
}

/* === Missing symbols from main.c === */
/* These are referenced by slapd code but defined only in main.c,
 * which we exclude from the fuzzing build. See Phasip's fuzzing.c
 * for the same approach. */

void parse_debug_unknowns(char *arg, int *level) {
    (void)arg;
    (void)level;
}

int parse_debug_level(const char *arg, int *level) {
    (void)arg;
    (void)level;
    return 0;
}

int parse_syslog_level(const char *arg, int *level) {
    (void)arg;
    (void)level;
    return 0;
}

int parse_syslog_user(const char *arg, int *level) {
    (void)arg;
    (void)level;
    return 0;
}

/* TLS globals referenced by slapd but not needed without TLS */
void *slap_tls_ld = (void *)0;
void *slap_tls_ctx = (void *)0;

/* === Missing backend/overlay init symbols === */
/* These are referenced by backends.o even with --enable-backends=no
 * because some backends (LDIF, monitor) are always compiled into the
 * backend table. We stub them out to avoid pulling in their full code. */

int overlay_init(void) { return 0; }

/* Backend init functions take a BackendInfo pointer; we use void* to
 * avoid needing the full slapd header chain here. */
int ldif_back_initialize(void *bi) { (void)bi; return 0; }
int monitor_back_initialize(void *bi) { (void)bi; return 0; }
