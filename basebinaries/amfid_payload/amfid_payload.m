#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>

#include "fishhook.h"
#include "cs_blobs.h"

static unsigned int
hash_rank(const CodeDirectory *cd)
{
    uint32_t type = cd->hashType;
    unsigned int n;
    
    for (n = 0; n < sizeof(hashPriorities) / sizeof(hashPriorities[0]); ++n)
        if (hashPriorities[n] == type)
            return n + 1;
    return 0;    /* not supported */
}

// see ldid.cpp around line 1250
uint8_t *get_hash(const CodeDirectory* directory, uint32_t* size) {
    uint32_t realsize = ntohl(directory->length);
    
    if (ntohl(directory->magic) != 0xfade0c02) {
        NSLog(@"[get_hash] wtf, not CSMAGIC_CODEDIRECTORY?!");
        return NULL;
    }
    
    // 2 uint32s in Blob (magic, length)
    // 7 uint32s in CodeDirectory (version, flags, ..., codeLimit)
    // 1 uint8 (hashSize)
    uint8_t hash_type = directory->hashType;
    
    uint8_t *out = NULL;
    if (hash_type == 1) {
        *size = CC_SHA1_DIGEST_LENGTH;
        out = malloc(*size);
        CC_SHA1(directory, realsize, out);
    } else if (hash_type == 2) {
        *size = CC_SHA256_DIGEST_LENGTH;
        out = malloc(*size);
        CC_SHA256(directory, realsize, out);
    } else {
        NSLog(@"[get_hash] Unknown hash type: 0x%x", hash_type);
        out = NULL;
    }
    
    return out;
}

//see cs_validate_csblob in xnu bsd/kern/ubc_subr.c
uint8_t *parse_superblob(uint8_t *code_dir, uint32_t *size){
    const CS_SuperBlob *sb = (const CS_SuperBlob *)code_dir;
    uint32_t* code_dir_int = (uint32_t*)code_dir;
    
    uint8_t *highest_cd_hash = NULL;
    uint8_t highest_cd_hash_rank = 0;
    
    for (int n = 0; n < ntohl(sb->count); n++){
        const CS_BlobIndex *blobIndex = &sb->index[n];
        uint32_t type = ntohl(blobIndex->type);
        uint32_t offset = ntohl(blobIndex->offset);
        if (ntohl(sb->length) < offset)
            return NULL;
        
        const CodeDirectory *subBlob = (const CodeDirectory *)(const void *)(code_dir + offset);
        size_t subLength = ntohl(subBlob->length);
        
        if (type == CSSLOT_CODEDIRECTORY || (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)) {
            uint8_t rank = hash_rank(subBlob);
            
            if (hash_rank(subBlob) > highest_cd_hash_rank){
                if (highest_cd_hash){
                    free(highest_cd_hash);
                    highest_cd_hash = NULL;
                }
                
                uint32_t newSize;
                uint8_t *cd_hash = get_hash(subBlob, &newSize);
                
                highest_cd_hash = cd_hash;
                highest_cd_hash_rank = rank;
                *size = newSize;
            }
        }
    }
    return highest_cd_hash;
}

uint8_t *get_code_directory(const char* name, uint64_t file_off) {
    // Assuming it is a macho

    FILE* fd = fopen(name, "r");

    if (fd == NULL) {
        NSLog(@"Couldn't open file");
        return NULL;
    }

    fseek(fd, 0L, SEEK_END);
    uint64_t file_len = ftell(fd);
    fseek(fd, 0L, SEEK_SET);

    if (file_off > file_len){
        NSLog(@"Error: File offset greater than length.");
        return NULL;
    }

    uint64_t off = file_off;
    fseek(fd, off, SEEK_SET);

    struct mach_header_64 mh;
    fread(&mh, sizeof(struct mach_header_64), 1, fd);

    if (mh.magic != MH_MAGIC_64){
        NSLog(@"Error: Invalid magic");
        return NULL;
    }

    off += sizeof(struct mach_header_64);
    if (off > file_len){
        NSLog(@"Error: Unexpected end of file");
        return NULL;
    }
    for (int i = 0; i < mh.ncmds; i++) {
        if (off + sizeof(struct load_command) > file_len){
            NSLog(@"Error: Unexpected end of file");
            return NULL;
        }

        const struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread((void*)&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == 0x1d) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);

            if (off_cs+file_off+size_cs > file_len){
                NSLog(@"Error: Unexpected end of file");
                return NULL;
            }

            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs+file_off, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            return cd;
        } else {
            off += cmd.cmdsize;
            if (off > file_len){
                NSLog(@"Error: Unexpected end of file");
                return NULL;
            }
        }
    }
    NSLog(@"Didnt find the code signature");
    return NULL;
}

int (*old_MISValidateSignatureAndCopyInfo)(NSString* file, NSDictionary* options, NSMutableDictionary** info);
int (*old_MISValidateSignatureAndCopyInfo_broken)(NSString* file, NSDictionary* options, NSMutableDictionary** info);

int fake_MISValidateSignatureAndCopyInfo(NSString* file, NSDictionary* options, NSMutableDictionary** info) {
    // NSString *file = (__bridge NSString *)fileStr;
    // NSDictionary *options = (__bridge NSDictionary*)opts;
    NSLog(@"We got called! %@ with %@ (info: %@)", file, options, *info);

    int origret = old_MISValidateSignatureAndCopyInfo(file, options, info);
    NSLog(@"We got called! AFTER ACTUAL %@ with %@ (info: %@)", file, options, *info);

    if (![*info objectForKey:@"CdHash"]) {
        NSNumber* file_offset = [options objectForKey:@"UniversalFileOffset"];
        uint64_t file_off = [file_offset unsignedLongLongValue];

        uint8_t* code_directory = get_code_directory([file UTF8String], file_off);
        if (!code_directory)
            return origret;

        uint32_t size;
        uint8_t* cd_hash = parse_superblob(code_directory, &size);

        if (!cd_hash)
            return origret;

        *info = [[NSMutableDictionary alloc] init];
        [*info setValue:[[NSData alloc] initWithBytes:cd_hash length:size] forKey:@"CdHash"];
        NSLog(@"ours: %@", *info);
        
        free(cd_hash);
    }

    return 0;
}

void rebind_mis(void) {
    void *libmis = dlopen("/usr/lib/libmis.dylib",RTLD_NOW); //Force binding now
    old_MISValidateSignatureAndCopyInfo = dlsym(libmis, "MISValidateSignatureAndCopyInfo");
    struct rebinding rebindings[] = {
        {"MISValidateSignatureAndCopyInfo", (void *)fake_MISValidateSignatureAndCopyInfo, (void **)&old_MISValidateSignatureAndCopyInfo_broken},
    };

    rebind_symbols(rebindings, 1);
}

__attribute__ ((constructor))
static void ctor(void) {
    rebind_mis();
}
