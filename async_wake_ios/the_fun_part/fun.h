//
//  fun.h
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#import <sys/mount.h>
#import <spawn.h>
#import <copyfile.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/utsname.h>

#include <mach/mach.h>

#include <pthread.h>

#include <CoreFoundation/CoreFoundation.h>

#include "kmem.h"
#include "find_port.h"
#include "kutils.h"
#include "symbols.h"
#include "early_kalloc.h"
#include "kcall.h"
#include "kdbg.h"
#include "patchfinder64.h"

#include "fun_objc.h"

kern_return_t mach_vm_read(
						   vm_map_t target_task,
						   mach_vm_address_t address,
						   mach_vm_size_t size,
						   vm_offset_t *data,
						   mach_msg_type_number_t *dataCnt);

/****** IOKit/IOKitLib.h *****/
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;

extern const mach_port_t kIOMasterPortDefault;
#define IO_OBJECT_NULL (0)

kern_return_t
IOConnectCallAsyncMethod(
						 mach_port_t     connection,
						 uint32_t        selector,
						 mach_port_t     wakePort,
						 uint64_t*       reference,
						 uint32_t        referenceCnt,
						 const uint64_t* input,
						 uint32_t        inputCnt,
						 const void*     inputStruct,
						 size_t          inputStructCnt,
						 uint64_t*       output,
						 uint32_t*       outputCnt,
						 void*           outputStruct,
						 size_t*         outputStructCntP);

kern_return_t
IOConnectCallMethod(
					mach_port_t     connection,
					uint32_t        selector,
					const uint64_t* input,
					uint32_t        inputCnt,
					const void*     inputStruct,
					size_t          inputStructCnt,
					uint64_t*       output,
					uint32_t*       outputCnt,
					void*           outputStruct,
					size_t*         outputStructCntP);

io_service_t
IOServiceGetMatchingService(
							mach_port_t  _masterPort,
							CFDictionaryRef  matching);

CFMutableDictionaryRef
IOServiceMatching(
				  const char* name);

kern_return_t
IOServiceOpen(
			  io_service_t  service,
			  task_port_t   owningTask,
			  uint32_t      type,
			  io_connect_t* connect );


void let_the_fun_begin(mach_port_t tfp0, mach_port_t user_client);

#endif /* fun_h */
