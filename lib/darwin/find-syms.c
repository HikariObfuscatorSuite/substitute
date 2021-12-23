#ifdef __APPLE__

#include <stdbool.h>
#include <stdlib.h>     //wangchuanju 2021-12-10
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <limits.h>
#include <fcntl.h>
#include <syslog.h>

#include "substitute.h"
#include "substitute-internal.h"
#include "dyld_cache_format.h"


static pthread_once_t dyld_inspect_once = PTHREAD_ONCE_INIT;
/* and its fruits: */

static const struct dyld_cache_header *_Atomic s_cur_shared_cache_hdr;
static int s_cur_shared_cache_fd;
static pthread_once_t s_open_cache_once = PTHREAD_ONCE_INIT;
static struct dyld_cache_local_symbols_info s_cache_local_symbols_info;
static struct dyld_cache_local_symbols_entry *s_cache_local_symbols_entries;

static bool oscf_try_dir(const char *dir, const char *arch,
                         const struct dyld_cache_header *dch) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s%s", dir,
                 DYLD_SHARED_CACHE_BASE_NAME, arch) >= sizeof(path))
        return false;
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    struct dyld_cache_header this_dch;
    if (read(fd, &this_dch, sizeof(this_dch)) != sizeof(this_dch))
        goto fail;
    if (memcmp(this_dch.uuid, dch->uuid, 16) ||
        this_dch.localSymbolsSize != dch->localSymbolsSize /* just in case */)
        goto fail;
    struct dyld_cache_local_symbols_info *lsi = &s_cache_local_symbols_info;
    if (pread(fd, lsi, sizeof(*lsi), dch->localSymbolsOffset) != sizeof(*lsi))
        goto fail;
    if (lsi->nlistOffset > dch->localSymbolsSize ||
        lsi->nlistCount > (dch->localSymbolsSize - lsi->nlistOffset)
                           / sizeof(substitute_sym) ||
        lsi->stringsOffset > dch->localSymbolsSize ||
        lsi->stringsSize > dch->localSymbolsSize - lsi->stringsOffset) {
        /* bad format */
        goto fail;
    }
    uint32_t count = lsi->entriesCount;
    if (count > 1000000)
        goto fail;
    struct dyld_cache_local_symbols_entry *lses;
    size_t lses_size = count * sizeof(*lses);
    if (!(lses = malloc(lses_size)))
        goto fail;
    if (pread(fd, lses, lses_size, dch->localSymbolsOffset + lsi->entriesOffset)
        != lses_size) {
        free(lses);
        goto fail;
    }

    s_cur_shared_cache_fd = fd;
    s_cache_local_symbols_entries = lses;
    return true;

fail:
    memset(lsi, 0, sizeof(*lsi));
    close(fd);
    return false;
}

static void open_shared_cache_file_once() {
    s_cur_shared_cache_fd = -1;
    const struct dyld_cache_header *dch = s_cur_shared_cache_hdr;
    if (memcmp(dch->magic, "dyld_v1 ", 8))
        return;
    if (dch->localSymbolsSize < sizeof(struct dyld_cache_local_symbols_info))
        return;
    const char *archp = &dch->magic[8];
    while (*archp == ' ')
        archp++;
    static char filename[32];
    const char *env_dir = getenv("DYLD_SHARED_CACHE_DIR");
    if (env_dir) {
        if (oscf_try_dir(env_dir, archp, dch))
            return;
    }
#if __IPHONE_OS_VERSION_MIN_REQUIRED
    oscf_try_dir(IPHONE_DYLD_SHARED_CACHE_DIR, archp, dch);
#else
    oscf_try_dir(MACOSX_DYLD_SHARED_CACHE_DIR, archp, dch);
#endif
}

static bool ul_mmap(int fd, off_t offset, size_t size,
                    void *data_p, void **mapping_p, size_t *mapping_size_p) {
    int pmask = getpagesize() - 1;
    int page_off = offset & pmask;
    off_t map_offset = offset & ~pmask;
    size_t map_size = ((offset + size + pmask) & ~pmask) - map_offset;
    void *mapping = mmap(NULL, map_size, PROT_READ, MAP_SHARED, fd, map_offset);
    if (mapping == MAP_FAILED)
        return false;
    *(void **) data_p = (char *) mapping + page_off;
    *mapping_p = mapping;
    *mapping_size_p = map_size;
    return true;
}

static bool get_shared_cache_syms(const void *hdr,
                                  const substitute_sym **syms_p,
                                  const char **strs_p,
                                  size_t *nsyms_p,
                                  void **mapping_p,
                                  size_t *mapping_size_p) {
    pthread_once(&s_open_cache_once, open_shared_cache_file_once);
    int fd = s_cur_shared_cache_fd;
    if (fd == -1)
        return false;
    const struct dyld_cache_header *dch = s_cur_shared_cache_hdr;
    const struct dyld_cache_local_symbols_info *lsi = &s_cache_local_symbols_info;
    struct dyld_cache_local_symbols_entry lse;
    for (uint32_t i = 0; i < lsi->entriesCount; i++) {
        lse = s_cache_local_symbols_entries[i];
        if (lse.dylibOffset == (uintptr_t) hdr - (uintptr_t) dch)
            goto got_lse;
    }
    return false;
got_lse:
    /* map - we don't do this persistently to avoid wasting address space on
     * iOS (my random OS X 10.10 blob pushes 55MB) */
    if (lse.nlistStartIndex > lsi->nlistCount ||
        lsi->nlistCount - lse.nlistStartIndex < lse.nlistCount)
        return false;

    char *ls_data;
    if (!ul_mmap(fd, dch->localSymbolsOffset, dch->localSymbolsSize,
                 &ls_data, mapping_p, mapping_size_p))
        return false;
    const substitute_sym *syms = (void *) (ls_data + lsi->nlistOffset);
    *syms_p = syms + lse.nlistStartIndex;
    *strs_p = ls_data + lsi->stringsOffset;
    *nsyms_p = lse.nlistCount;
    return true;
}



static const struct dyld_cache_header *get_cur_shared_cache_hdr() {
    const struct dyld_cache_header *dch = s_cur_shared_cache_hdr;
    if (!dch) {
        /* race is OK */
        uint64_t start_address = 0;
        //wangchuanju 2021-12-02: syscall() was deprecated from macOS 10.12  ++[
        int (*syscall)(int, uint64_t *);
        syscall = (int (*)(int, uint64_t *))dlsym(RTLD_DEFAULT, "syscall");
        //]++
        if (syscall(294, &start_address)) /* SYS_shared_region_check_np */
            dch = (void *) 1;
        else
            dch = (void *) (uintptr_t) start_address;
        s_cur_shared_cache_hdr = dch;
    }
    return dch == (void *) 1 ? NULL : dch;
}

static bool addr_in_shared_cache(const void *addr) {
    const struct dyld_cache_header *dch = get_cur_shared_cache_hdr();
    if (!dch)
        return false;

    uint32_t mapping_count = dch->mappingCount;
    const struct dyld_cache_mapping_info *mappings =
        (void *) ((char *) dch + dch->mappingOffset);
    intptr_t slide = (uintptr_t) dch - (uintptr_t) mappings[0].address;

    for (uint32_t i = 0; i < mapping_count; i++) {
        const struct dyld_cache_mapping_info *mapping = &mappings[i];
        uintptr_t diff = (uintptr_t) addr -
                         ((uintptr_t) mapping->address + slide);
        if (diff < mapping->size)
            return true;
    }
    return false;
}


/**
 * Compatible with dyld3.  wangchuanju 2021-12-07
 */
static const void *get_symbol_addr(const mach_header_x *machHeader, const char *symbolName)
{
    fprintf(stderr, "get_symbol_addr -- machHeader: %#lx , symbolName: %s \n", (uintptr_t)machHeader, symbolName);

    if (!machHeader) {
        return NULL;
    }
    
    bool is_64 = false;
    if (machHeader->magic == MH_MAGIC_64)
        is_64 = true;
    else if (machHeader->magic == MH_MAGIC)
        is_64 = false;
    
    uint32_t ncmds = machHeader->ncmds;
    const struct symtab_command *symtab = NULL;
    uintptr_t firstVmaddr = 0;
    uintptr_t linkeditVmaddr = 0;
    uint64_t linkeditFileoff = 0;
    
    struct load_command *lc = NULL;
    if (machHeader->magic == MH_MAGIC_64)
        lc = (struct load_command *) ((void*)machHeader + sizeof(struct mach_header_64));
    else if (machHeader->magic == MH_MAGIC)
        lc = (struct load_command *) ((void*)machHeader + sizeof(struct mach_header));
    else
        fprintf(stderr, "invalid mach header magic value: %#x  \n", machHeader->magic);
    
    for (unsigned i = 0; i < ncmds; i++, lc = (void*)lc + lc->cmdsize) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (void *)lc;
            if (!firstVmaddr && sc->filesize) {
                firstVmaddr = sc->vmaddr;
            }
            if ( strcmp(sc->segname, "__LINKEDIT") == 0 ) {
                linkeditVmaddr = sc->vmaddr;
                linkeditFileoff = sc->fileoff;
            }
        } else if (lc->cmd == LC_SEGMENT) {
            const struct segment_command *sc = (void *)lc;
            if (!firstVmaddr && sc->filesize) {
                firstVmaddr = sc->vmaddr;
            }
            if ( strcmp(sc->segname, "__LINKEDIT") == 0 ) {
                linkeditVmaddr = sc->vmaddr;
                linkeditFileoff = sc->fileoff;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab = (struct symtab_command*)lc;
        }
        if (symtab && linkeditVmaddr) break;
    }
    
    if (!symtab || !linkeditVmaddr) return NULL;
    
    

    const char *string_table = ((void*)machHeader + symtab->stroff - linkeditFileoff + linkeditVmaddr -firstVmaddr);
    
    if (is_64) {
        const struct nlist_64 *symbols = (typeof (symbols))
            ((void*)machHeader + symtab->symoff - linkeditFileoff + linkeditVmaddr -firstVmaddr);
    
        for (unsigned i = 0; i < symtab->nsyms; i++) {
          if (strcmp((char*)(string_table + symbols[i].n_un.n_strx), symbolName) == 0) {
              const void *addr = (void *)machHeader + symbols[i].n_value - firstVmaddr;
              fprintf(stderr, "get_symbol_addr -- symbol addr: %#lx\n", (uintptr_t)addr);
              return addr;
          }
        }
    } else {
        const struct nlist *symbols = (typeof (symbols))
            ((void*)machHeader + symtab->symoff - linkeditFileoff + linkeditVmaddr - firstVmaddr);
    
        for (unsigned i = 0; i < symtab->nsyms; i++) {
          if (strcmp((char*)(string_table + symbols[i].n_un.n_strx), symbolName) == 0) {
              const void *addr = (void *)machHeader + symbols[i].n_value - firstVmaddr;
              fprintf(stderr, "get_symbol_addr -- symbol addr: %#lx\n", (uintptr_t)addr);
              return addr;
          }
        }
    }
      
    return NULL;
}


// static void *sym_to_ptr(const substitute_sym *sym, intptr_t slide) {
//     uintptr_t addr = sym->n_value;
//     addr += slide;
//     if (sym->n_desc & N_ARM_THUMB_DEF)
//         addr |= 1;
//     return (void *) addr;
// }

// static void find_syms_raw(const void *hdr, intptr_t *restrict slide,
//                           const char **restrict names, void **restrict syms,
//                           size_t nsyms) {
//     fprintf(stderr, "find_syms_raw 00000 - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//     memset(syms, 0, sizeof(*syms) * nsyms);

//     void *mapping = NULL;
//     size_t mapping_size = 0;
//     const substitute_sym *cache_syms = NULL;
//     const char *cache_strs = NULL;
//     size_t ncache_syms = 0;
//     fprintf(stderr, "find_syms_raw 11111 - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//     if (addr_in_shared_cache(hdr)) {
//         fprintf(stderr, "find_syms_raw 22222 - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//         get_shared_cache_syms(hdr, &cache_syms, &cache_strs, &ncache_syms,
//                               &mapping, &mapping_size);
//         fprintf(stderr, "find_syms_raw 33333 - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//     }

//     /* note: no verification at all */
//     const mach_header_x *mh = hdr;
//     uint32_t ncmds = mh->ncmds;
//     struct load_command *lc = (void *) (mh + 1);
//     struct symtab_command syc;
//     for (uint32_t i = 0; i < ncmds; i++) {
//         if (lc->cmd == LC_SYMTAB) {
//             syc = *(struct symtab_command *) lc;
//             goto ok;
//         }
//         lc = (void *) lc + lc->cmdsize;
//     }
//     return; /* no symtab, no symbols */
// ok: ;
//     fprintf(stderr, "find_syms_raw 55555 ok - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//     substitute_sym *symtab = NULL;
//     const char *strtab = NULL;
//     lc = (void *) (mh + 1);
//     for (uint32_t i = 0; i < ncmds; i++) {
//         if (lc->cmd == LC_SEGMENT_X) {
//             segment_command_x *sc = (void *) lc;
//             if (syc.symoff - sc->fileoff < sc->filesize)
//                 symtab = (void *) sc->vmaddr + syc.symoff - sc->fileoff;
//             if (syc.stroff - sc->fileoff < sc->filesize)
//                 strtab = (void *) sc->vmaddr + syc.stroff - sc->fileoff;
//             if (*slide == -1 && sc->fileoff == 0) {
//                 // used only for dyld
//                 *slide = (uintptr_t) hdr - sc->vmaddr;
//             }
//             if (symtab && strtab)
//                 goto ok2;
//         }
//         lc = (void *) lc + lc->cmdsize;
//     }
//     return; /* uh... weird */
// ok2: ;
//     fprintf(stderr, "find_syms_raw 66666 ok2 - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//     symtab = (void *) symtab + *slide;
//     strtab = (void *) strtab + *slide;
//     size_t found_syms = 0;

//     for (int type = 0; type <= 1; type++) {
//         const substitute_sym *this_symtab = type ? cache_syms : symtab;
//         const char *this_strtab = type ? cache_strs : strtab;
//         size_t this_nsyms = type ? ncache_syms : syc.nsyms;
//         /* This could be optimized for efficiency with a large number of
//          * names... */
//         for (uint32_t i = 0; i < this_nsyms; i++) {
//             const substitute_sym *sym = &this_symtab[i];
//             uint32_t strx = sym->n_un.n_strx;
//             const char *name = strx == 0 ? "" : this_strtab + strx;
//             for (size_t j = 0; j < nsyms; j++) {
//                 if (!syms[j] && !strcmp(name, names[j])) {
//                     syms[j] = sym_to_ptr(sym, *slide);
//                     if (++found_syms == nsyms)
//                         goto end;
//                 }
//             }
//         }
//     }

// end:
//     fprintf(stderr, "find_syms_raw 99999 end - hdr: %#lx , *names[0]: %s,  \n", (long)hdr, *names);
//     if (mapping_size)
//         munmap(mapping, mapping_size);
// }

/* This is a mess because the usual _dyld_image_count loop is not thread safe.
 * Since it uses a std::vector and (a) erases from it (making it possible for a
 * loop to skip entries) and (b) and doesn't even lock it in
 * _dyld_get_image_header etc., this is true even if the image is guaranteed to
 * be found, including the possibility to crash.  How do we solve this?
 * Inception - we steal dyld's private symbols...  We could avoid the symbols
 * by calling the vtable of dlopen handles, but that seems unstable.  As is,
 * the method used is somewhat convoluted in an attempt to maximize stability.
 */

// static void inspect_dyld() {
//     // const struct dyld_all_image_infos *aii = _dyld_get_all_image_infos();
//     //wangchuanju 2021-12-2 ++[
//     task_t task = current_task();
//     kern_return_t kr;
//     task_flavor_t flavor = TASK_DYLD_INFO;
//     task_dyld_info_data_t infoData;
//     mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
//     kr = task_info(task, flavor, (task_info_t) &infoData, &task_info_outCnt);
//     if (kr != KERN_SUCCESS) {
//         printf("Failed read task_info.\n");
//         return;
//     }
//     const struct dyld_all_image_infos *aii = (struct dyld_all_image_infos *) infoData.all_image_info_addr;
//     //wangchuanju 2021-11-30 ]++

//     const void *dyld_hdr = aii->dyldImageLoadAddress;

//     // const char *names[2] = { "__ZNK16ImageLoaderMachO8getSlideEv",
//     //                          "__ZNK16ImageLoaderMachO10machHeaderEv" };
//     //wang chuanju 2021-12-03
//     //const char *names[1] = { "__ZNK5dyld311MachOLoaded8getSlideEv"};    //dyld3::MachOLoaded::getSlide() const
//     const char *names[1] = { "__ZN5dyld44APIs21_dyld_get_image_slideEPK11mach_header"};    //dyld4::APIs::_dyld_get_image_slide(mach_header const*)

//     //void *syms[2];
//     void *syms[1];      //wangchuanju 2021-12-03
//     intptr_t dyld_slide = -1;
//     //find_syms_raw(dyld_hdr, &dyld_slide, names, syms, 2);
//     find_syms_raw(dyld_hdr, &dyld_slide, names, syms, 1);       //wangchuanju 2021-12-03
//     s_dyld_slide = dyld_slide;      //wangchuanju 2021-12-03
//     //if (!syms[0] || !syms[1])
//     if (!syms[0])       //wangchuanju 2021-12-03
//         substitute_panic("couldn't find ImageLoader methods\n");

//     //ImageLoaderMachO_getSlide = syms[0];
//     MachOLoaded_getSlide = syms[0];        //wang chuanju 2021-12-03
//     //ImageLoaderMachO_machHeader = syms[1];    //wang chuanju 2021-12-03
//     fprintf(stderr, "inspect_dyld 99999 - MachOLoaded_getSlide: %#lx , dlerror: %s \n", (long)MachOLoaded_getSlide, dlerror());
// }


/**
 * Compatible with dyld3.    wangchuanju 2021-12-07
 */
static const struct mach_header_x *get_header_by_path(const char *filePath)
{
    fprintf(stderr, "get_header_by_path --  filePath: %s\n", filePath);

    task_t task = current_task();
    kern_return_t kr;
    task_flavor_t flavor = TASK_DYLD_INFO;
    task_dyld_info_data_t infoData;
    mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, flavor, (task_info_t) &infoData, &task_info_outCnt);
    if (kr != KERN_SUCCESS) {
        //KR_ERROR(kr);
        //std::cout << "Failed read task_info.\n";
        fprintf(stderr, "Failed read task_info.\n");
        return NULL;
    }
    
    struct dyld_all_image_infos *aii = (struct dyld_all_image_infos *) infoData.all_image_info_addr;

    fprintf(stderr, "get_header_by_path: got dyld_all_image_infos -- aii->infoArrayCount : %d\n", aii->infoArrayCount );
    
    for (unsigned i = 0; i < aii->infoArrayCount; i++) {
        // If the version of LLVM is not suitable for Xcode, maybe the strcmp could return unresaonable result.
        //    Xcode 13.1 -- LLVM 12.0
        if (strcmp(aii->infoArray[i].imageFilePath, filePath) == 0) {
            return (const struct mach_header_x *) aii->infoArray[i].imageLoadAddress;
        }
    }
    return NULL;
}


/**
 * Compatible with dyld3.    wangchuanju 2021-12-07
 */
static const uintptr_t get_slide(mach_header_x *machHeader) {
    if (!machHeader) {
        return 0;
    }
    
    uintptr_t slide = 0;
    uint32_t ncmds = machHeader->ncmds;
    struct load_command *lc = NULL;
    if (machHeader->magic == MH_MAGIC_64)
        lc = (struct load_command *) ((void*)machHeader + sizeof(struct mach_header_64));
    else if (machHeader->magic == MH_MAGIC)
        lc = (struct load_command *) ((void*)machHeader + sizeof(struct mach_header));
    else
        fprintf(stderr, "invalid mach header magic value: %#x  \n", machHeader->magic);
    
    for (unsigned i = 0; i < ncmds; i++, lc = (void*)lc + lc->cmdsize) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sc = (void *)lc;
            if ( strcmp(sc->segname, "__TEXT") == 0 ) {
                slide = (uintptr_t) ((uint64_t)machHeader - sc->vmaddr);
                break;
            }
        } else if (lc->cmd == LC_SEGMENT) {
            const struct segment_command *sc = (void *)lc;
            if ( strcmp(sc->segname, "__TEXT") == 0 ) {
                slide = (uintptr_t) ((uint64_t)machHeader - sc->vmaddr);
                break;
            }
        }
    }
    return slide;
}

/**
 * Compatible with dyld3.   wangchuanju 2021-12-07
 */
/* 'dlhandle' keeps the image alive */
EXPORT
struct substitute_image *substitute_open_image(const char *filename) {
    fprintf(stderr, "substitute_open_image (find-syms.c) - filename: %s \n", filename);

    char *realFilePath = realpath(filename, NULL);      //wangchuanju 2021-12-07

    fprintf(stderr, "substitute_open_image (find-syms.c) - realFilePath: %s \n", realFilePath);

    if (!realFilePath)
        substitute_panic("substitute_open_image (find-syms.c) failed: can not get the file path : %s \n", filename);

    //pthread_once(&dyld_inspect_once, inspect_dyld);
    // void *dlhandle = dlopen(filename, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
    void *dlhandle = dlopen(realFilePath, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
    if (!dlhandle)
        substitute_panic("substitute_open_image (find-syms.c) failed: %s \n", dlerror());

    // const void *image_header = ImageLoaderMachO_machHeader(dlhandle);
    // intptr_t slide = ImageLoaderMachO_getSlide(dlhandle);
    const void *machHeader = get_header_by_path(realFilePath);              //wangchuanju 2021-12-07
    if (!machHeader)
        substitute_panic("substitute_open_image (find-syms.c) -- get_header_by_path failed: machHeader: %#lx , for file: %s \n", (uintptr_t)machHeader, realFilePath);

    const uintptr_t slide = get_slide((mach_header_x*)machHeader);      //wangchuanju 2021-12-07
    if (!slide)
        substitute_panic("substitute_open_image (find-syms.c) -- get_slide failed: : %#lx , for machHeader: %#lx \n", slide, (uintptr_t)machHeader);

    struct substitute_image *im = malloc(sizeof(*im));
    if (!im)
        return NULL;
    im->slide = slide;
    im->dlhandle = dlhandle;
    im->image_header = machHeader;      //image_header;

    if (!realFilePath) 
        free(realFilePath);

    fprintf(stderr, "substitute_open_image - return:  dlhandle: %#lx , image_header: %#lx , slide: %#lx , file: %s \n", (intptr_t)im->dlhandle, (intptr_t)im->image_header, (intptr_t)im->slide, realFilePath);

    return im;
}

EXPORT
void substitute_close_image(struct substitute_image *im) {
    dlclose(im->dlhandle); /* ignore errors */
    free(im);
}

EXPORT
int substitute_find_private_syms(struct substitute_image *im,
                                 const char **restrict names,
                                 void **restrict syms,
                                 size_t nsyms) {
    fprintf(stderr, "substitute_find_private_syms - im: %#lx , names[0]: %s  \n", (intptr_t)im, names[0]);

    //find_syms_raw(im->image_header, &im->slide, names, syms, nsyms);
    //wangchuanju 2021-12-07
    for (unsigned i=0; i < nsyms; i++) {
        syms[i] = (void*)get_symbol_addr(im->image_header, names[i]);
    }
    return SUBSTITUTE_OK;
}

#endif /* __APPLE__ */
