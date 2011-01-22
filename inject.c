#include "inject.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h> // xx remove this

struct dyld_all_image_infos {
    uint32_t version;
    uint32_t infoArrayCount;
    uint32_t infoArray;
    uint32_t notification;
    uint8_t processDetachedFromSharedRegion;
    uint8_t libSystemInitialized;
    uint8_t pad[2];
    uint32_t dyldImageLoadAddress;
};

struct dyld_all_image_infos_64 {
    uint32_t version;
    uint32_t infoArrayCount;
    uint64_t infoArray;
    uint64_t notification;
    uint8_t processDetachedFromSharedRegion;
    uint8_t libSystemInitialized;
    uint8_t pad[6];
    uint64_t dyldImageLoadAddress;
};

#define ARM_THREAD_STATE 1
struct arm_thread_state {
    uint32_t r[13];
    uint32_t sp;
    uint32_t lr;
    uint32_t pc;
    uint32_t cpsr;
};

#define x86_THREAD_STATE32 1
struct x86_thread_state32 {
    uint32_t eax, ebx, ecx, edx,
             edi, esi, ebp, esp,
             ss, eflags, eip,
             cs, ds, es, fs, gs;
};

#define x86_THREAD_STATE64 4
struct x86_thread_state64 {
    uint64_t rax, rbx, rcx, rdx,
             rdi, rsi, rbp, rsp,
             r8, r9, r10, r11,
             r12, r13, r14, r15,
             rip, rflags,
             cs, fs, gs;
};

#define PPC_THREAD_STATE64 5
struct ppc_thread_state64 {
    uint64_t srr0, srr1;
    uint64_t r[32];
    uint32_t cr;
    uint64_t xer, lr, ctr;
    uint32_t vrsave;
};

static const vm_size_t stack_size = 32*1024;

struct addr_bundle {
    mach_vm_address_t dlopen;
    mach_vm_address_t mach_thread_self;
    mach_vm_address_t thread_terminate;
    mach_vm_address_t syscall;
};

static inline void handle_sym(const char *sym, mach_vm_address_t value, struct addr_bundle *bundle) {
    switch(sym[1]) {
    case 'd':
        if(!strcmp(sym, "_dlopen")) bundle->dlopen = value;
        break;
    case 'm':
        if(!strcmp(sym, "_mach_thread_self")) bundle->mach_thread_self = value;
        break;
    case 's':
        if(!strcmp(sym, "_syscall")) bundle->syscall = value;
        break;
    case 't':
        if(!strcmp(sym, "_thread_terminate")) bundle->thread_terminate = value;
        break;
    }
}

#define TRY(x) if(kr = x) { if(failure_string) *failure_string = #x; goto bad; }
#define address_cast(x) ((mach_vm_address_t) (uintptr_t) (x))
#define SWAP(x) (swap ? __builtin_bswap32(x) : (x))
#define SWAP64(x) (swap ? __builtin_bswap64(x) : (x))

static kern_return_t get_stuff(task_t task, cpu_type_t *cputype, struct addr_bundle *bundle, const char **failure_string) {
#ifdef __arm__
    *cputype = CPU_TYPE_ARM;
    bundle->dlopen = (mach_vmess_t) &dlopen;
    bundle->mach_thread_self = (mach_vmess_t) &mach_thread_self;
    bundle->thread_terminate = (mach_vmess_t) &thread_terminate;
    return 0;
#else
    kern_return_t kr;
    task_dyld_info_data_t info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    union {
        struct dyld_all_image_infos data;
        struct dyld_all_image_infos_64 data64;
    } u;
    mach_vm_size_t data_size;

    struct mach_header mach_hdr;
    struct load_command *cmds = 0, *lc;
    uint32_t ncmds;
    mach_vm_size_t sizeofcmds;
    bool proc64, swap, mh64;
    size_t nlist_size;
    uint32_t symoff = 0, nsyms, stroff, strsize;
    mach_vm_address_t straddr = 0, symaddr = 0;
    char *strs = 0; void *syms = 0;

    TRY(task_info(task, TASK_DYLD_INFO, (task_info_t) &info, &count));
        
    data_size = sizeof(u);
    if(info.all_image_info_size < data_size) data_size = info.all_image_info_size;

    TRY(mach_vm_read_overwrite(task, info.all_image_info_addr, data_size, address_cast(&u), &data_size));

    if(u.data.version == 1) return KERN_NO_SPACE;

    // Try to guess whether the process is 64-bit,
    proc64 = info.all_image_info_addr > 0xffffffff;

    mach_vm_address_t dyldImageLoadAddress = proc64 ? u.data64.dyldImageLoadAddress : u.data.dyldImageLoadAddress;

    TRY(mach_vm_read_overwrite(task, dyldImageLoadAddress, sizeof(mach_hdr), address_cast(&mach_hdr), &data_size));

    swap = mach_hdr.magic == MH_CIGAM || mach_hdr.magic == MH_CIGAM_64;
    mh64 = mach_hdr.magic == MH_MAGIC_64 || mach_hdr.magic == MH_CIGAM_64;

    *cputype = SWAP(mach_hdr.cputype);

    nlist_size = mh64 ? sizeof(struct nlist_64) : sizeof(struct nlist);

    sizeofcmds = SWAP(mach_hdr.sizeofcmds);
    cmds = malloc(sizeofcmds);

    TRY(mach_vm_read_overwrite(task, dyldImageLoadAddress + (mh64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header)), sizeofcmds, address_cast(cmds), &sizeofcmds));

    lc = cmds;
    ncmds = SWAP(mach_hdr.ncmds);
    while(ncmds--) {
        if(SWAP(lc->cmd) == LC_SYMTAB) {
            struct symtab_command *sc = (void *) lc;
            symoff = SWAP(sc->symoff);
            nsyms = SWAP(sc->nsyms);
            if(nsyms >= 1000000) {
                kr = KERN_INVALID_ARGUMENT;
                goto bad;
            }
            stroff = SWAP(sc->stroff);
            strsize = SWAP(sc->strsize);
        }
        lc = (void *) ((char *) lc + SWAP(lc->cmdsize));
    }

    if(!symoff) {
        kr = KERN_INVALID_ARGUMENT;
        goto bad;
    }

    lc = cmds;
    ncmds = SWAP(mach_hdr.ncmds);
    while(ncmds--) {
        if(SWAP(lc->cmd) == LC_SEGMENT) {
            struct segment_command *sc = (void *) lc;
            if(SWAP(sc->fileoff) < symoff && (SWAP(sc->fileoff) + SWAP(sc->filesize)) >= (symoff + nsyms * nlist_size)) {
                symaddr = sc->vmaddr + symoff - sc->fileoff; 
            }
            if(SWAP(sc->fileoff) < stroff && (SWAP(sc->fileoff) + SWAP(sc->filesize)) >= (stroff + strsize)) {
                straddr = sc->vmaddr + stroff - sc->fileoff; 
            }
        } else if(SWAP(lc->cmd) == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (void *) lc;
            if(SWAP64(sc->fileoff) < symoff && (SWAP64(sc->fileoff) + SWAP64(sc->filesize)) >= (symoff + nsyms * nlist_size)) {
                symaddr = sc->vmaddr + symoff - sc->fileoff; 
            }
            if(SWAP64(sc->fileoff) < stroff && (SWAP64(sc->fileoff) + SWAP64(sc->filesize)) >= (stroff + strsize)) {
                straddr = sc->vmaddr + stroff - sc->fileoff; 
            }
        }
        lc = (void *) ((char *) lc + SWAP(lc->cmdsize));
    }

    if(!straddr || !symaddr) {
        kr = KERN_INVALID_ARGUMENT;
        goto bad;
    }

    strs = malloc(strsize);
    syms = malloc(nsyms * nlist_size);
    TRY(mach_vm_read_overwrite(task, straddr, strsize, address_cast(strs), &data_size));
    TRY(mach_vm_read_overwrite(task, symaddr, nsyms * nlist_size, address_cast(syms), &data_size));

    memset(bundle, 0, sizeof(*bundle));

    if(mh64) {
        const struct nlist_64 *nl = syms;
        while(nsyms--) {
            handle_sym(strs + SWAP(nl->n_un.n_strx), (mach_vm_address_t) SWAP64(nl->n_value), bundle);
            nl++;
        }
    } else {
        const struct nlist *nl = syms;
        while(nsyms--) {
            handle_sym(strs + SWAP(nl->n_un.n_strx), (mach_vm_address_t) SWAP(nl->n_value), bundle);
            nl++;
        }
    }

    if(!bundle->dlopen || !bundle->mach_thread_self || !bundle->thread_terminate) {
        kr = KERN_INVALID_ADDRESS;
        goto bad;
    }
    printf("%llx %llx\n", symaddr, straddr);


    kr = 0;
bad:
    if(cmds) free(cmds);
    if(strs) free(strs);
    if(syms) free(syms);
    return kr;
#endif
}

kern_return_t inject(pid_t pid, const char *path, const char **failure_string) {
    kern_return_t kr;

    task_t task = 0;
    thread_act_t thread = 0;
    mach_vm_address_t stack_address = 0, stack_end;
    mach_vm_address_t trampoline_address = 0;
    thread_state_t state;
    thread_state_flavor_t state_flavor;
	mach_msg_type_number_t state_count;
    struct addr_bundle bundle;
    cpu_type_t cputype;

    void *trampoline;
    
    if(failure_string) *failure_string = 0;

    TRY(task_for_pid(mach_task_self(), (int) pid, &task));

    if(kr = get_stuff(task, &cputype, &bundle, failure_string)) goto bad;

#define TRAMP(array...) { uint8_t tramp[] = {array}; TRY(mach_vm_write(task, trampoline_address, address_cast(&tramp), sizeof(tramp))); TRY(mach_vm_protect(task, trampoline_address, 0x1000, 0, VM_PROT_READ | VM_PROT_EXECUTE)); }

    TRY(mach_vm_allocate(task, &trampoline_address, 0x1000, VM_FLAGS_ANYWHERE));

    TRY(mach_vm_allocate(task, &stack_address, stack_size, VM_FLAGS_ANYWHERE));

    printf("trampoline_address=%llx stack_address=%llx\n", trampoline_address, stack_address);

    stack_end = stack_address + stack_size - 0x100;

    TRY(mach_vm_write(task, stack_address, address_cast(path), strlen(path) + 1));

    uint32_t args_32[] = {360, (uint32_t) bundle.dlopen, (uint32_t) stack_address, 128*1024, 0, 0};
    uint64_t args_64[] = {360, (uint64_t) bundle.dlopen, (uint64_t) stack_address, 128*1024, 0, 0};

    if(cputype == CPU_TYPE_ARM) {
        // blx r4; blx r5; blx r6
        TRAMP(0x34, 0xff, 0x2f, 0xe1,
              0x35, 0xff, 0x2f, 0xe1,
              0x36, 0xff, 0x2f, 0xe1);

        struct arm_thread_state arm_state;
        memset(&arm_state, 0, sizeof(arm_state));
        memcpy(&arm_state.r[0], args_32, 4*4);
        TRY(mach_vm_write(task, stack_end, address_cast(args_32 + 4), 2*4));

        arm_state.r[4] = (uint32_t) bundle.syscall;
        arm_state.r[5] = (uint32_t) bundle.mach_thread_self;
        arm_state.r[6] = (uint32_t) bundle.thread_terminate;
        arm_state.sp = (uint32_t) stack_end;
        arm_state.pc = (uint32_t) trampoline_address;

        state = (void *) &arm_state;
        state_flavor = ARM_THREAD_STATE;
        state_count = sizeof(arm_state) / sizeof(*state);
    } else if(cputype == CPU_TYPE_X86) {
        // call ecx; call edi; push eax; call esi
        TRAMP(0xff, 0xd1, 0xff, 0xd7, 0x50, 0xff, 0xd6);

        struct x86_thread_state32 x86_state;
        memset(&x86_state, 0, sizeof(x86_state));
        
        TRY(mach_vm_write(task, stack_end, address_cast(args_32), 6*4));

        x86_state.ecx = (uint32_t) bundle.syscall;
        x86_state.edi = (uint32_t) bundle.mach_thread_self;
        x86_state.esi = (uint32_t) bundle.thread_terminate;
        x86_state.esp = x86_state.ebp = (uint32_t) stack_end;
        x86_state.eip = (uint32_t) trampoline_address;

        state = (void *) &x86_state;
        state_flavor = x86_THREAD_STATE32;
        state_count = sizeof(x86_state) / sizeof(*state);
    } else if(cputype == CPU_TYPE_X86_64) {
        // callq r12; callq r13; mov rdi, rax; callq r14
        TRAMP(0x41, 0xff, 0xd4,
              0x41, 0xff, 0xd5,
              0x48, 0x89, 0xc7,
              0x41, 0xff, 0xd6);

        struct x86_thread_state64 x86_state;
        memset(&x86_state, 0, sizeof(x86_state));
        x86_state.rdi = args_64[0];
        x86_state.rsi = args_64[1];
        x86_state.rdx = args_64[2];
        x86_state.rcx = args_64[3];
        x86_state.r8  = args_64[4];
        x86_state.r9  = args_64[5];

        x86_state.r12 = bundle.syscall;
        x86_state.r13 = 0xdeadbeef;//bundle.mach_thread_self;
        x86_state.r14 = bundle.thread_terminate;
        x86_state.rsp = x86_state.rbp = stack_end;
        x86_state.rip = trampoline_address;

        state = (void *) &x86_state;
        state_flavor = x86_THREAD_STATE64;
        state_count = sizeof(x86_state) / sizeof(*state);
    } else if(cputype == CPU_TYPE_POWERPC || cputype == CPU_TYPE_POWERPC64) {
        // bctrl; mtctr r13; bctrl; mtctr r14; bctrl
        TRAMP(0x4e, 0x80, 0x04, 0x21,
              0x7d, 0xa9, 0x03, 0xa6,
              0x4e, 0x80, 0x04, 0x21,
              0x7d, 0xc9, 0x03, 0xa6,
              0x4e, 0x80, 0x04, 0x21);

        struct ppc_thread_state64 ppc_state;
        memset(&ppc_state, 0, sizeof(ppc_state));
        ppc_state.r[1] = stack_end;
        memcpy(&ppc_state.r[3], args_64, 6*8);
        ppc_state.ctr = bundle.syscall;
        ppc_state.r[13] = bundle.mach_thread_self;
        ppc_state.r[14] = bundle.thread_terminate;
        ppc_state.srr0 = trampoline_address;
        
        state = (void *) &ppc_state;
        state_flavor = PPC_THREAD_STATE64;
        state_count = sizeof(ppc_state) / sizeof(*state);
    } else {
        abort();
    }

    TRY(thread_create_running(task, state_flavor, state, state_count, &thread));

    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), task);

    return KERN_SUCCESS;    

bad:
    if(stack_address) vm_deallocate(task, stack_address, stack_size);
    if(trampoline_address) vm_deallocate(task, trampoline_address, sizeof(trampoline));
    if(thread) {
        thread_terminate(thread);
        mach_port_deallocate(mach_task_self(), thread);
    }
    if(task) {
        mach_port_deallocate(mach_task_self(), task);
    }
    return kr;
}
