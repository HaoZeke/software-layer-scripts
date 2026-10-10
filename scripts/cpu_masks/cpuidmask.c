/*
 * cpuidmask: present an older x86 CPU to every dynamically linked process in a
 * tree, without a VM.
 *
 * The constructor turns on CPUID faulting for the process (arch_prctl
 * ARCH_SET_CPUID 0), so each CPUID instruction raises SIGSEGV. The handler
 * runs the real CPUID with faulting briefly off, applies the mask for the
 * requested profile, writes the result into the trapped context and steps past
 * the two-byte instruction. Faulting resets on execve, so the library has to
 * stay in LD_PRELOAD for children to inherit the view.
 *
 * Programs that install their own SIGSEGV handler (GCC's cc1, GNU grep's
 * stack-overflow guard) would otherwise take the trap themselves, so sigaction
 * and signal are interposed: the program's SIGSEGV handler is recorded, ours
 * stays installed, and every fault that is not a CPUID is passed to theirs.
 *
 * Profile is chosen with CPUIDMASK_PROFILE: zen4, zen3, zen2 or icelake.
 * CPUIDMASK_RULES=FILE takes the rules from a file instead, as gen_profile.py
 * writes them from a target's recorded compiler flags: one rule per line,
 *   clear LEAF SUB REG MASK      replace LEAF SUB REG VALUE
 * with REG 0 to 3 for EAX to EDX; '#' starts a comment.
 * CPUIDMASK_STRICT=1 exits with status 97 when the kernel has no CPUID
 * faulting, instead of running with the real CPU visible.
 * Limits: statically linked binaries and code that runs before constructors
 * (the dynamic loader's own CPU probe) see the real CPU.
 */
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>
#include <cpuid.h>

/* Leaves whose output depends on the subleaf in ECX. For the others ECX is
 * ignored by the CPU and may hold anything, so rules match subleaf 0. */
static int has_subleaves(uint32_t leaf)
{
    switch (leaf) {
    case 0x4: case 0x7: case 0xb: case 0xd: case 0xf: case 0x10: case 0x12:
    case 0x14: case 0x17: case 0x18: case 0x19: case 0x1d: case 0x1e: case 0x1f:
    case 0x20: case 0x23: case 0x24: case 0x8000001d: case 0x80000020: case 0x80000026:
        return 1;
    }
    return 0;
}

struct rule { uint32_t leaf, sub; int reg; uint32_t clear, set; int replace; uint32_t value; };
enum { EAX, EBX, ECX, EDX };
#define LEAF7(sub, reg, bit) { 0x00000007, sub, reg, 1u << (bit), 0, 0, 0 }

/* Zen 4 view of a Zen 5 part: the five ISA features GCC's znver5 adds, plus
 * family 19h model 11h (Genoa) in the signature leaves. */
static const struct rule zen4_rules[] = {
    { 0x00000001, 0, EAX, 0, 0, 1, 0x00A10F11 },
    { 0x80000001, 0, EAX, 0, 0, 1, 0x00A10F11 },
    LEAF7(0, EDX, 8),   /* AVX512_VP2INTERSECT */
    LEAF7(0, ECX, 27),  /* MOVDIRI */
    LEAF7(0, ECX, 28),  /* MOVDIR64B */
    LEAF7(1, EAX, 4),   /* AVX_VNNI */
    LEAF7(1, EDX, 14),  /* PREFETCHI */
};

/* Zen 3 view, from GCC's PTA_ZNVER3 = PTA_ZNVER4 minus the AVX-512 family and
 * GFNI: everything zen4 clears, plus those, with family 19h model 01h (Milan). */
#define ZEN5_DELTA LEAF7(0, EDX, 8), LEAF7(0, ECX, 27), LEAF7(0, ECX, 28), LEAF7(1, EAX, 4), LEAF7(1, EDX, 14)
#define ZEN4_DELTA \
    { 0x00000007, 0, EBX, (1u << 16) | (1u << 17) | (1u << 21) | (1u << 28) | (1u << 30) | (1u << 31), 0, 0, 0 }, \
    { 0x00000007, 0, ECX, (1u << 1) | (1u << 6) | (1u << 8) | (1u << 11) | (1u << 12) | (1u << 14), 0, 0, 0 }, \
    LEAF7(1, EAX, 5)
static const struct rule zen3_rules[] = {
    { 0x00000001, 0, EAX, 0, 0, 1, 0x00A00F11 },
    { 0x80000001, 0, EAX, 0, 0, 1, 0x00A00F11 },
    ZEN5_DELTA, ZEN4_DELTA,
};

/* Zen 2 view, from PTA_ZNVER2 = PTA_ZNVER3 minus VAES, VPCLMULQDQ and PKU,
 * family 17h model 31h (Rome). */
static const struct rule zen2_rules[] = {
    { 0x00000001, 0, EAX, 0, 0, 1, 0x00830F10 },
    { 0x80000001, 0, EAX, 0, 0, 1, 0x00830F10 },
    ZEN5_DELTA, ZEN4_DELTA,
    { 0x00000007, 0, ECX, (1u << 3) | (1u << 4) | (1u << 9) | (1u << 10), 0, 0, 0 },  /* PKU, OSPKE, VAES, VPCLMULQDQ */
};

/* Ice Lake-SP view of a Zen 4/5 part. Vendor and signature become Intel
 * (family 6, model 6Ah); every feature Ice Lake lacks is cleared, including the
 * AMD-only ones, because GCC's -march=native turns each visible CPUID bit into
 * an -m flag regardless of vendor. */
static const struct rule icelake_rules[] = {
    { 0x00000000, 0, EBX, 0, 0, 1, 0x756e6547 },  /* "Genu" */
    { 0x00000000, 0, EDX, 0, 0, 1, 0x49656e69 },  /* "ineI" */
    { 0x00000000, 0, ECX, 0, 0, 1, 0x6c65746e },  /* "ntel" */
    { 0x00000001, 0, EAX, 0, 0, 1, 0x000606A6 },
    { 0x80000000, 0, EBX, 0, 0, 1, 0 },
    { 0x80000000, 0, ECX, 0, 0, 1, 0 },
    { 0x80000000, 0, EDX, 0, 0, 1, 0 },
    { 0x80000001, 0, EAX, 0, 0, 1, 0 },
    { 0x80000001, 0, ECX, (1u << 6) | (1u << 7) | (1u << 29), 0, 0, 0 },  /* SSE4A, MISALIGNSSE, MONITORX */
    { 0x80000008, 0, EBX, (1u << 0) | (1u << 4), 0, 0, 0 },   /* CLZERO, RDPRU */
    LEAF7(0, EDX, 8),   /* AVX512_VP2INTERSECT */
    LEAF7(0, ECX, 27),  /* MOVDIRI */
    LEAF7(0, ECX, 28),  /* MOVDIR64B */
    LEAF7(1, EAX, 4),   /* AVX_VNNI */
    LEAF7(1, EAX, 5),   /* AVX512_BF16 */
    LEAF7(1, EDX, 14),  /* PREFETCHI */
    LEAF7(0, ECX, 7),   /* CET_SS: Ice Lake server has no shadow stack */
};

static unsigned long ntrapped;
static const struct rule *rules;
static size_t nrules;
static struct rule file_rules[64];

/* Read CPUIDMASK_RULES; returns the number of rules, or -1 on any bad line. */
static long load_rules(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[256], kind[16];
    unsigned long leaf, sub, reg, val;
    size_t n = 0;
    long rc = 0;
    while (fgets(line, sizeof line, f)) {
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        if (sscanf(line, "%15s", kind) != 1) continue;
        if (n == sizeof file_rules / sizeof *file_rules
            || sscanf(line, "%15s %li %li %li %li", kind, (long *)&leaf, (long *)&sub, (long *)&reg, (long *)&val) != 5
            || reg > EDX) { rc = -1; break; }
        struct rule r = { (uint32_t)leaf, (uint32_t)sub, (int)reg, 0, 0, 0, 0 };
        if (strcmp(kind, "clear") == 0) r.clear = (uint32_t)val;
        else if (strcmp(kind, "replace") == 0) { r.replace = 1; r.value = (uint32_t)val; }
        else { rc = -1; break; }
        file_rules[n++] = r;
    }
    fclose(f);
    return rc < 0 ? -1 : (long)n;
}

static long set_cpuid(int on) { return syscall(SYS_arch_prctl, ARCH_SET_CPUID, on); }

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn real_sigaction;
static int armed;
/* The program's own SIGSEGV disposition, which ours forwards to. */
static struct sigaction user_segv = { .sa_handler = SIG_DFL };

static void forward(int sig, siginfo_t *si, void *ctx)
{
    if (user_segv.sa_flags & SA_SIGINFO) {
        user_segv.sa_sigaction(sig, si, ctx);
    } else if (user_segv.sa_handler == SIG_IGN) {
        return;
    } else if (user_segv.sa_handler != SIG_DFL) {
        user_segv.sa_handler(sig);
    } else {
        /* Default action: restore it and return, so the fault repeats and kills. */
        struct sigaction dfl = { .sa_handler = SIG_DFL };
        sigemptyset(&dfl.sa_mask);
        real_sigaction(SIGSEGV, &dfl, NULL);
    }
}

static void on_segv(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = ctx;
    greg_t *g = uc->uc_mcontext.gregs;
    const unsigned char *ip = (const unsigned char *)g[REG_RIP];
    if (!(ip[0] == 0x0f && ip[1] == 0xa2)) {
        forward(sig, si, ctx);
        return;
    }
    ntrapped++;
    uint32_t leaf = (uint32_t)g[REG_RAX], sub = (uint32_t)g[REG_RCX];
    uint32_t r[4];
    set_cpuid(1);
    __cpuid_count(leaf, sub, r[EAX], r[EBX], r[ECX], r[EDX]);
    set_cpuid(0);
    for (size_t i = 0; i < nrules; i++) {
        const struct rule *ru = &rules[i];
        if (ru->leaf != leaf || ru->sub != (has_subleaves(leaf) ? sub : 0)) continue;
        if (ru->replace) r[ru->reg] = ru->value;
        else r[ru->reg] = (r[ru->reg] & ~ru->clear) | ru->set;
    }
    g[REG_RAX] = r[EAX]; g[REG_RBX] = r[EBX]; g[REG_RCX] = r[ECX]; g[REG_RDX] = r[EDX];
    g[REG_RIP] += 2;
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *old)
{
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (sig != SIGSEGV || !armed)
        return real_sigaction(sig, act, old);
    if (old)
        *old = user_segv;
    if (act)
        user_segv = *act;
    return 0;
}

sighandler_t signal(int sig, sighandler_t handler)
{
    struct sigaction act, old;
    memset(&act, 0, sizeof act);
    act.sa_handler = handler;
    act.sa_flags = SA_RESTART;
    sigemptyset(&act.sa_mask);
    if (sigaction(sig, &act, &old) < 0)
        return SIG_ERR;
    return old.sa_handler;
}

/* CPUIDMASK_STATS=1: report how many CPUIDs this process had answered. */
__attribute__((destructor)) static void cpuidmask_fini(void)
{
    if (armed && getenv("CPUIDMASK_STATS")) {
        char buf[96];
        int n = snprintf(buf, sizeof buf, "cpuidmask: pid %d answered %lu cpuid\n", (int)getpid(), ntrapped);
        if (n > 0) (void)!write(2, buf, (size_t)n);
    }
}

__attribute__((constructor)) static void cpuidmask_init(void)
{
    const char *p = getenv("CPUIDMASK_PROFILE");
    const char *rf = getenv("CPUIDMASK_RULES");
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (rf && *rf) {
        long n = load_rules(rf);
        if (n < 0) {
            static const char msg[] = "cpuidmask: cannot read CPUIDMASK_RULES; CPUID not masked\n";
            (void)!write(2, msg, sizeof msg - 1);
            return;
        }
        rules = file_rules; nrules = (size_t)n;
    } else if (!p) {
        return;
    } else if (strcmp(p, "zen4") == 0) {
        rules = zen4_rules; nrules = sizeof zen4_rules / sizeof *zen4_rules;
    } else if (strcmp(p, "zen3") == 0) {
        rules = zen3_rules; nrules = sizeof zen3_rules / sizeof *zen3_rules;
    } else if (strcmp(p, "zen2") == 0) {
        rules = zen2_rules; nrules = sizeof zen2_rules / sizeof *zen2_rules;
    } else if (strcmp(p, "icelake") == 0) {
        rules = icelake_rules; nrules = sizeof icelake_rules / sizeof *icelake_rules;
    } else {
        return;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    real_sigaction(SIGSEGV, &sa, NULL);
    armed = 1;
    if (set_cpuid(0) != 0) {
        /* No CPUID faulting (AMD: Linux 6.17, or a kernel with the backport):
         * every CPUID would see the real CPU. CPUIDMASK_STRICT=1 stops the
         * process so a build cannot go on unmasked. */
        static const char msg[] = "cpuidmask: CPUID faulting unavailable; CPUID is not masked\n";
        (void)!write(2, msg, sizeof msg - 1);
        if (getenv("CPUIDMASK_STRICT")) _exit(97);
    }
}
