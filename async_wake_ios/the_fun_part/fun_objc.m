//
//  fun_objc.m
//  async_wake_ios
//
//  Created by George on 16/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include <dlfcn.h>
#include <copyfile.h>
#include <stdio.h>
#include <spawn.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#import <Foundation/Foundation.h>


const char* binaryName() {
	char path[4096];
	uint32_t size = sizeof(path);
	_NSGetExecutablePath(path, &size);
	char *pt = realpath(path, NULL);
	
	NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];
	
	NSString *bootstrap = [execpath stringByAppendingPathComponent:@"test_fsigned"];
	return [bootstrap UTF8String];
}

const char* launchctlpath() {
	char path[4096];
	uint32_t size = sizeof(path);
	_NSGetExecutablePath(path, &size);
	char *pt = realpath(path, NULL);
	
	NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];
	
	NSString *bootstrap = [execpath stringByAppendingPathComponent:@"launchctl"];
	return [bootstrap UTF8String];
}
const char* plistPath2() {
	char path[4096];
	uint32_t size = sizeof(path);
	_NSGetExecutablePath(path, &size);
	char *pt = realpath(path, NULL);
	
	NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];
	
	NSString *bootstrap = [execpath stringByAppendingPathComponent:@"test_fsigned.plist"];
	return [bootstrap UTF8String];
}

const char* realPath() {
	char path[4096];
	uint32_t size = sizeof(path);
	_NSGetExecutablePath(path, &size);
	char *pt = realpath(path, NULL);
	return pt;
}
