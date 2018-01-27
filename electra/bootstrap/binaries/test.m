// xcrun -sdk iphoneos gcc -dynamiclib -arch arm64 -framework Foundation -o test.dylib test.m
// jtool --sign --inplace test.dylib

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

__attribute__ ((constructor))
static void ctor(void) {
	NSLog(@"Unsigned dylib!!");
}
