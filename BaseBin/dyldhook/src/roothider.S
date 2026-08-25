#define MAKE_TRAMPOLINE_ALIAS(to, alias) .global _##alias %% .global _MACHOMERGER_TRAMPOLINE_##to## %% _##alias: %% _MACHOMERGER_TRAMPOLINE_##to##: %% b .
#define MAKE_TRAMPOLINE(to) MAKE_TRAMPOLINE_ALIAS(to, to)

#define SYSCALL_PROLOGUE stp x0, x1, [sp, -16]! %% stp x2, x3, [sp, -16]! %% stp x4, x5, [sp, -16]! %% stp x6, x7, [sp, -16]!
#define SYSCALL_EPILOGUE ldp x6, x7, [sp], 16 %% ldp x4, x5, [sp], 16 %% ldp x2, x3, [sp], 16 %% ldp x0, x1, [sp], 16

#define DEF_SYSCALL(name, num)  .global _##name %% _##name: %% SYSCALL_PROLOGUE %% mov x16, num %% svc #0x80 %% mov x16, x0 %% SYSCALL_EPILOGUE %% bcc name##_end %% cmp x16, #4 %% beq _##name %% mov x16, #-1 %% name##_end: %% mov x0, x16 %% ret
#define DEF_MACHTRAP(name, num) .global _##name %% _##name: %% mov x16, -num %% svc #0x80 %% ret
#define DEF_ALIAS(to, from) .global _##to %% _##to: %% b _##from

.text
.align 4


// RootHide port (Kernel-JB adaptation): COMMENTED OUT the strlcpy + strlcat
// trampolines because Kernel-JB's main.S (lines 70-71) already defines them.
// Relaxin's main.S doesn't define these, so they need to be in roothider.S;
// but Kernel-JB's main.S does, causing duplicate-symbol link errors:
//   duplicate symbol '_strlcpy' in: main.o roothider.o
//   duplicate symbol '_MACHOMERGER_TRAMPOLINE_strlcat' in: main.o roothider.o
//   duplicate symbol '_MACHOMERGER_TRAMPOLINE_strlcpy' in: main.o roothider.o
//   duplicate symbol '_strlcat' in: main.o roothider.o
// We only need the _MACHOMERGER_ORIG_* trampoline for the dyld
// expandAtLoaderPath hook (which is what roothider.c uses), kept below.
//MAKE_TRAMPOLINE(strlcpy)
//MAKE_TRAMPOLINE(strlcat)

.global _MACHOMERGER_ORIG__ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc
.global _MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc
_MACHOMERGER_ORIG__ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc:
    nop // Will be replaced with the original first instruction by machomerger
    // FALLTHROUGH
_MACHOMERGER_HOOKTRAMPOLINE__ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc:
    b .
