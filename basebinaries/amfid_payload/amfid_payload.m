#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <string.h>             // strerror
#include <sys/mman.h>           // mmap
#include <sys/stat.h>           // fstat

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>

#include "fishhook.h"
#include "cs_blobs.h"

// %@ is used in this file!
#define LOG(str, args...) do { NSLog(@"" str, ##args); } while(0)
#define ERROR(str, args...) LOG("ERROR: [%s] " str, __func__, ##args)
#define INFO(str, args...)  LOG("INFO : [%s] " str, __func__, ##args)

static unsigned int
hash_rank(const CodeDirectory *cd)
{
    uint32_t type = cd->hashType;
    unsigned int n;
    
    for (n = 0; n != sizeof(hashPriorities) / sizeof(hashPriorities[0]); ++n)
        if (hashPriorities[n] == type)
            return n + 1;
    return 0;    /* not supported */
}

// 0 on success
int hash_code_directory(const CodeDirectory* directory, uint8_t dst[CS_CDHASH_LEN]) {
    uint32_t realsize = ntohl(directory->length);
    
    if (ntohl(directory->magic) != CSMAGIC_CODEDIRECTORY) {
        ERROR("expected CSMAGIC_CODEDIRECTORY");
        return 1;
    }
    
    uint8_t out[CS_HASH_MAX_SIZE];
    uint8_t hash_type = directory->hashType;

    switch (hash_type) {
        case CS_HASHTYPE_SHA1:
            CC_SHA1(directory, realsize, out);
            break;

        case CS_HASHTYPE_SHA256:
        case CS_HASHTYPE_SHA256_TRUNCATED:
            CC_SHA256(directory, realsize, out);
            break;

        case CS_HASHTYPE_SHA384:
            CC_SHA384(directory, realsize, out);
            break;

        default:
            INFO("Unknown hash type: 0x%x", hash_type);
            return 2;
    }

    memcpy(dst, out, CS_CDHASH_LEN);
    return 0;
}

#define BLOB_FITS(blob, size) ((size >= sizeof(*blob)) && (size <= ntohl(blob->length)))

// see cs_validate_csblob in xnu bsd/kern/ubc_subr.c
// 0 on success
int hash_code_signature(const void *csblob, uint32_t csblob_size, uint8_t dst[CS_CDHASH_LEN]) {
    const CS_GenericBlob *gb = (const CS_GenericBlob *) csblob;
    if (!BLOB_FITS(gb, csblob_size)) {
        ERROR("csblob too small even for generic blob");
        return 1;
    }

    const CodeDirectory *chosen_cd = NULL;

    if (ntohl(gb->magic) == CSMAGIC_EMBEDDED_SIGNATURE) {
        uint8_t highest_cd_hash_rank = 0;

        const CS_SuperBlob *sb = (const CS_SuperBlob *) csblob;
        if (!BLOB_FITS(sb, csblob_size)) {
            ERROR("csblob too small for superblob");
            return 1;
        }

        uint32_t sblength = ntohl(sb->length);
        
        for (int i = 0; i != ntohl(sb->count); ++i){
            const CS_BlobIndex *blobIndex = &sb->index[i];

            uint32_t type = ntohl(blobIndex->type);
            uint32_t offset = ntohl(blobIndex->offset);

            if (offset > sblength) {
                ERROR("offset of blob #%d overflows superblob length", i);
                return 1;
            }
            
            if (type == CSSLOT_CODEDIRECTORY || (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
                const CodeDirectory *subcd = (const CodeDirectory *)((uintptr_t)csblob + offset);
                
                if (!BLOB_FITS(subcd, sblength - offset)) {
                    ERROR("subblob codedirectory doesnt fit in superblob");
                    return 1;
                }

                uint8_t rank = hash_rank(subcd);
                
                if (rank > highest_cd_hash_rank) {
                    chosen_cd = subcd;
                    highest_cd_hash_rank = rank;
                }
            }
        }
    } else if (ntohl(gb->magic) == CSMAGIC_CODEDIRECTORY) {
        const CodeDirectory *cd = (const CodeDirectory *) csblob;
        if (!BLOB_FITS(cd, csblob_size)) {
            ERROR("csblob too small for codedirectory");
            return 1;
        }
        chosen_cd = cd;
    } else {
        ERROR("Unknown magic at csblob start: %08x", ntohl(gb->magic));
        return 1;
    }

    if (chosen_cd == NULL) {
        ERROR("Didnt find codedirectory to hash");
        return 1;
    }

    return hash_code_directory(chosen_cd, dst);
}

typedef struct {
    const char* name;
    uint64_t file_off;
    int fd;

    // mmap(name) + file_off
    const void* addr;
    // file size - file_off
    size_t size;
} img_info_t;

void close_img(img_info_t* info) {
    if (info == NULL) {
        return;
    }

    if (info->addr != NULL) {
        const void *map = (void*) ((uintptr_t) info->addr - info->file_off);
        size_t fsize = info->size + info->file_off;

        munmap((void*)map, fsize);
    }

    if (info->fd != -1) {
        close(info->fd);
    }
}

// 0 on success
int open_img(img_info_t* info) {
#define _LOG_ERROR(str, args...) ERROR("(%s) " str, info->name, ##args)
    int ret = -1;

    if (info == NULL) {
        INFO("img info is NULL");
        return ret;
    }

    info->fd = -1;
    info->size = 0;
    info->addr = NULL;

    info->fd = open(info->name, O_RDONLY);
    if (info->fd == -1) {
        _LOG_ERROR("Couldn't open file");
        ret = 1; goto out;
    }

    struct stat s;
    if (fstat(info->fd, &s) != 0) {
        _LOG_ERROR("fstat: 0x%x (%s)", errno, strerror(errno));
        ret = 2; goto out;
    }

    size_t fsize = s.st_size;

    // overflow me!
    if (sizeof(struct mach_header_64) + info->file_off > fsize){
        _LOG_ERROR("File too small to have mach header at file_off (off + sizeof(mh) > fsize)");
        ret = 3; goto out;
    }

    info->size = fsize - info->file_off;
    const void *map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, info->fd, 0);

    if (map == MAP_FAILED) {
        _LOG_ERROR("mmap: 0x%x (%s)", errno, strerror(errno));
        ret = 4; goto out;
    }

    info->addr = (const void*) ((uintptr_t) map + info->file_off);

out:;
    if (ret) {
        close_img(info);
    }
    return ret;

#undef _LOG_ERROR
}

const uint8_t *find_code_signature(img_info_t* info, uint32_t* cs_size) {
#define _LOG_ERROR(str, args...) ERROR("(%s) " str, info->name, ##args)
    if (info == NULL || info->addr == NULL) {
        return NULL;
    }

    const struct mach_header_64* mh = (const struct mach_header_64*) info->addr;

    if (mh->magic != MH_MAGIC_64) {
        _LOG_ERROR("Invalid magic %08x", mh->magic);
        return NULL;
    }

    if (mh->sizeofcmds < mh->ncmds * sizeof(struct load_command)) {
        _LOG_ERROR("Corrupted macho (sizeofcmds < ncmds * sizeof(lc))");
        return NULL;
    }
    if (mh->sizeofcmds + sizeof(struct mach_header_64) > info->size) {
        _LOG_ERROR("Corrupted macho (sizeofcmds + sizeof(mh) > size)");
        return NULL;     
    }

    const struct load_command *cmd = (const struct load_command *) &mh[1];
    for (int i = 0; i != mh->ncmds; ++i) {
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            const struct linkedit_data_command* cscmd = (const struct linkedit_data_command*) cmd;
            if (cscmd->dataoff + cscmd->datasize > info->size){
                _LOG_ERROR("Corrupted LC_CODE_SIGNATURE: dataoff + datasize > fsize");
                return NULL;
            }

            if (cs_size) {
                *cs_size = cscmd->datasize;
            }

            return (const uint8_t*) ((uintptr_t) info->addr + cscmd->dataoff);
        }

        cmd = (const struct load_command *) ((uintptr_t)cmd + cmd->cmdsize);
        if ((uintptr_t)cmd + sizeof(struct load_command) > (uintptr_t)info->addr + info->size) {
            _LOG_ERROR("Corrupted macho: Unexpected end of file while parsing load commands");
            return NULL;
        }
    }
    
    _LOG_ERROR("Didnt find the code signature");
    return NULL;
#undef _LOG_ERROR
}

int (*old_MISValidateSignatureAndCopyInfo)(NSString* file, NSDictionary* options, NSMutableDictionary** info);

int fake_MISValidateSignatureAndCopyInfo(NSString* file, NSDictionary* options, NSMutableDictionary** info) {
    INFO(@"[%@] We got called! %@ (info: %@)", file, options, info ? *info : nil);
    
    int ret = old_MISValidateSignatureAndCopyInfo(file, options, info);

    INFO(@"[%@] Original func: %d (info: %@)", file, ret, info ? *info : nil);

    if (info != NULL) {
        if (*info == NULL) {
            *info = [[NSMutableDictionary alloc] init];
            if (*info == nil) {
                ERROR("Out of memory -- cant alloc info");
                goto out;
            }
        }

        if (![*info objectForKey:@"CdHash"]) {
            // theoretically options can be nil
            // then we get:
            //  [nil objectForKey:@"UniversalFileOffset"] => nil
            //  [nil unsignedLongLongValue] => 0
            // Means that we get file_off = 0 if options is nil
            // so we're fine

            NSNumber* file_offset = [options objectForKey:@"UniversalFileOffset"];
            uint64_t file_off = [file_offset unsignedLongLongValue];

            img_info_t img;
            img.name = file.UTF8String;
            img.file_off = file_off;

            if (open_img(&img)) {
                ERROR(@"[%@] Failed to open file", file);
                goto out;
            }

            uint32_t cs_length;
            const uint8_t* cs = find_code_signature(&img, &cs_length);
            if (cs == NULL) {
                ERROR(@"[%@] Cant find code_signature", file);
                goto closeimg;
            }

            uint8_t cd_hash[CS_CDHASH_LEN];

            if (hash_code_signature(cs, cs_length, cd_hash)) {
                ERROR(@"[%@] Failed to get cdhash from code signature", file);
                goto closeimg;
            }

            NSData *ns_cd_hash = [[NSData alloc] initWithBytes:cd_hash length:sizeof(cd_hash)];
            [*info setValue:ns_cd_hash forKey:@"CdHash"];

            INFO(@"[%@] info after ours: %@", file, *info);

            ret = 0;
closeimg:;
            close_img(&img);
        } else {
            // old func has done our job
            ret = 0;
        }
    } else {
        // when info is NULL we always return 0
        ret = 0;
    }

out:;
    return ret;
}

void rebind_mis(void) {
    // so apparenly fishhook has some bug which is being workarounded here 

    // Force binding now (XXX why?)
    void *libmis = dlopen("/usr/lib/libmis.dylib", RTLD_NOW);
    old_MISValidateSignatureAndCopyInfo = dlsym(libmis, "MISValidateSignatureAndCopyInfo");

    // dlclose leak but who cares: since it's all in shared cache
    // and even if it wasn't we're loaded into amfid -- which has
    // LC_LOAD_DYLIB(libmis)

    void *broken;
    struct rebinding rebindings[] = {
        {"MISValidateSignatureAndCopyInfo", (void *)fake_MISValidateSignatureAndCopyInfo, &broken},
    };

    rebind_symbols(rebindings, sizeof(rebindings) / sizeof(*rebindings));
}

__attribute__ ((constructor))
static void ctor(void) {
    rebind_mis();
}
