#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach-o/loader.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>

#include "fishhook.h"

uint32_t swap_uint32(uint32_t val) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

// see ldid.cpp around line 1250
uint8_t *get_hash(uint8_t* code_dir, uint32_t* size) {
    uint32_t* code_dir_int = (uint32_t*)code_dir;

    int cd_off = 0;
    while (code_dir_int[cd_off] != 0) {
        cd_off += 1;
    }
    cd_off += 1;
    int actual_off = swap_uint32(code_dir_int[cd_off]);

    code_dir_int = (uint32_t*)(code_dir+actual_off);
    uint32_t realsize = swap_uint32(code_dir_int[1]);

    if (swap_uint32(code_dir_int[0]) != 0xfade0c02) {
        NSLog(@"[get_hash] wtf, not CSMAGIC_CODEDIRECTORY?!");
        return NULL;
    }

    // 2 uint32s in Blob (magic, length)
    // 7 uint32s in CodeDirectory (version, flags, ..., codeLimit)
    // 1 uint8 (hashSize)
    uint8_t hash_type = ((uint8_t*)code_dir_int)[9*4 + 1];

    // uint32_t realsize = 0;
    // for (int j = 0; j < 1000; j++) {
    //     if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
    //         realsize = swap_uint32(code_dir_int[j+1]);
    //         code_dir += 4*j;
    //     }
    // }

    uint8_t *out = NULL;
    if (hash_type == 1) {
        *size = CC_SHA1_DIGEST_LENGTH;
        out = malloc(*size);
        CC_SHA1(code_dir_int, realsize, out);
    } else if (hash_type == 2) {
        *size = CC_SHA256_DIGEST_LENGTH;
        out = malloc(*size);
        CC_SHA256(code_dir_int, realsize, out);
    } else {
        NSLog(@"[get_hash] Unknown hash type: 0x%x", hash_type);
        out = NULL;
    }

    return out;
}

uint8_t *get_code_directory(const char* name, uint64_t file_off) {
	// Assuming it is a macho

	FILE* fd = fopen(name, "r");

    if (fd == NULL) {
        NSLog(@"Couldn't open file");
        return NULL;
    }

    uint64_t off = file_off;
    fseek(fd, off, SEEK_SET);

	struct mach_header_64 mh;
	fread(&mh, sizeof(struct mach_header_64), 1, fd);

	off += sizeof(struct mach_header_64);
	for (int i = 0; i < mh.ncmds; i++) {
		const struct load_command cmd;
		fseek(fd, off, SEEK_SET);
		fread((void*)&cmd, sizeof(struct load_command), 1, fd);
		if (cmd.cmd == 0x1d) {
			uint32_t off_cs;
			fread(&off_cs, sizeof(uint32_t), 1, fd);
			uint32_t size_cs;
			fread(&size_cs, sizeof(uint32_t), 1, fd);

			uint8_t *cd = malloc(size_cs);
			fseek(fd, off_cs+file_off, SEEK_SET);
			fread(cd, size_cs, 1, fd);
			return cd;
		} else {
			off += cmd.cmdsize;
		}
	}
    NSLog(@"Didnt find the code signature");
	return NULL;
}

int (*old_MISValidateSignatureAndCopyInfo)(NSString* file, NSDictionary* options, NSMutableDictionary** info);

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
        uint8_t* cd_hash = get_hash(code_directory, &size);

        if (!cd_hash)
            return origret;

        *info = [[NSMutableDictionary alloc] init];
        [*info setValue:[[NSData alloc] initWithBytes:cd_hash length:size] forKey:@"CdHash"];
        NSLog(@"ours: %@", *info);
    }

    return 0;
}

void rebind_mis(void) {
    struct rebinding rebindings[] = {
        {"MISValidateSignatureAndCopyInfo", (void *)fake_MISValidateSignatureAndCopyInfo, (void **)&old_MISValidateSignatureAndCopyInfo},
    };

    rebind_symbols(rebindings, 1);
}

__attribute__ ((constructor))
static void ctor(void) {
    rebind_mis();
}
