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
#import "NSData+GZip.h"

const char* progname(const char* prog) {
    char path[4096];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char *pt = realpath(path, NULL);

    NSString *execpath = [[NSString stringWithUTF8String:pt] stringByDeletingLastPathComponent];

    NSString *bootstrap = [execpath stringByAppendingPathComponent:[NSString stringWithUTF8String:prog]];
    return [bootstrap UTF8String];
}

const char* realPath() {
	char path[4096];
	uint32_t size = sizeof(path);
	_NSGetExecutablePath(path, &size);
	char *pt = realpath(path, NULL);
	return pt;
}

void extractTarBinary(){
    NSData *tarGz = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"tar" ofType:@"gz"]];
    NSData *tar = [tarGz gunzippedData];
    [tar writeToFile:@"/bootstrap/tar" atomically:YES];
}

void update_springboard_plist(){
    NSDictionary *springBoardPlist = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [springBoardPlist setValue:@YES forKey:@"SBShowNonDefaultSystemApps"];
    [springBoardPlist writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    
    NSDictionary* attr = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithShort:0755], NSFilePosixPermissions,@"mobile",NSFileOwnerAccountName,NULL];
    
    NSError *error = nil;
    [[NSFileManager defaultManager] setAttributes:attr ofItemAtPath:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" error:&error];
}
