#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>

#ifdef __LP64__
#define nlist_native nlist_64
#define LC_SEGMENT_NATIVE LC_SEGMENT_64
#define segment_command_native segment_command_64
#define mach_header_native mach_header_64
#define section_native section_64
#define PAGEZERO_SIZE 0x100000000;
#else
#define nlist_native nlist
#define LC_SEGMENT_NATIVE LC_SEGMENT
#define segment_command_native segment_command
#define mach_header_native mach_header
#define section_native section
#define PAGEZERO_SIZE 0x1000
#endif

void *find_lazy(uint32_t ncmds, struct load_command *cmds, const char *desired) {
    uint32_t symoff = 0, stroff = 0, isymoff = 0, lazy_index = 0, lazy_size = 0;
    void **lazy = 0;
    struct load_command *lc;
    uint32_t cmdsleft;

    lc = cmds;
    for(cmdsleft = ncmds; cmdsleft--;) {
        printf("%p %x\n", &lc->cmd, lc->cmd);
        if(lc->cmd == LC_SYMTAB) {
            struct symtab_command *sc = (void *) lc;
            stroff = sc->stroff;
            symoff = sc->symoff;
        } else if(lc->cmd == LC_DYSYMTAB) {
            struct dysymtab_command *dc = (void *) lc;
            isymoff = dc->indirectsymoff;
        } else if(lc->cmd == LC_SEGMENT_NATIVE) {
            struct segment_command_native *sc = (void *) lc;
            struct section_native *sect = (void *) (sc + 1);
            uint32_t i;
            for(i = 0; i < sc->nsects; i++) {
                if((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
                    lazy_index = sect->reserved1; 
                    lazy_size = sect->size / sizeof(*lazy);
                    lazy = (void *) sect->addr;
                }
                sect++;    
            }
        }
        lc = (void *) ((char *) lc + lc->cmdsize);
    }

    if(!stroff || !symoff || !isymoff || !lazy_index) return 0;

#define CATCH(off, addr) if(sc->fileoff <= (off) && (sc->fileoff + sc->filesize) >= (off)) (addr) = (void *) (sc->vmaddr + (off) - sc->fileoff);
    struct nlist_native *syms = 0;
    char *strs = 0;
    uint32_t *isyms = 0;

    lc = cmds;
    for(cmdsleft = ncmds; cmdsleft--;) {
        if(lc->cmd == LC_SEGMENT_NATIVE) {
            struct segment_command_native *sc = (void *) lc;
            CATCH(symoff, syms);
            CATCH(stroff, strs);
            CATCH(isymoff, isyms);
        }
        lc = (void *) ((char *) lc + lc->cmdsize);
    }

    if(!syms || !strs || !isyms) return 0;

    uint32_t i;
    for(i = lazy_index; i < lazy_index + lazy_size; i++) {
        struct nlist_native *sym = syms + isyms[i];
        if(!strcmp(strs + sym->n_un.n_strx, desired)) {
            return lazy;
        }
        lazy++;
    }

    return 0;
}

bool interpose(const char *name, void *impl) {
    struct mach_header_native *mach_hdr = (void *)PAGEZERO_SIZE;

    void **lazy = find_lazy(mach_hdr->ncmds, (void *) (mach_hdr + 1), name);
    if(!lazy) return false;
    
    *lazy = impl;

    return true;
}
