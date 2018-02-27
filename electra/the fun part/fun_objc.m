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
#import "ViewController.h"
#import "utils.h"

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

void extractGz(const char *from, const char *to) {
    NSData *gz = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@(from) ofType:@"gz"]];
    NSData *extracted = [gz gunzippedData];
    [extracted writeToFile:@(to) atomically:YES];
}

void update_springboard_plist(){
    NSDictionary *springBoardPlist = [NSMutableDictionary dictionaryWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [springBoardPlist setValue:@YES forKey:@"SBShowNonDefaultSystemApps"];
    [springBoardPlist writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    
    NSDictionary* attr = [NSDictionary dictionaryWithObjectsAndKeys:[NSNumber numberWithShort:0755], NSFilePosixPermissions,@"mobile",NSFileOwnerAccountName,NULL];
    
    NSError *error = nil;
    [[NSFileManager defaultManager] setAttributes:attr ofItemAtPath:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" error:&error];
}

void startDaemons(){    
    pid_t pd;
    
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/etc/rc.d" error:nil];
    for (NSString *fileName in files){
        NSString *fullPath = [@"/etc/rc.d" stringByAppendingPathComponent:fileName];
        run([fullPath UTF8String]);
    }
    
    files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/Library/LaunchDaemons/" error:nil];
    for (NSString *fileName in files){
        if ([fileName isEqualToString:@"jailbreakd.plist"])
            continue;
        if ([fileName isEqualToString:@"com.openssh.sshd.plist"])
            continue;
        
        NSString *fullPath = [@"/Library/LaunchDaemons" stringByAppendingPathComponent:fileName];
        
        posix_spawn(&pd, "/bin/launchctl", NULL, NULL, (char **)&(const char*[]){ "launchctl", "load", [fullPath UTF8String], NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
}

void displaySnapshotNotice(){
    [[ViewController currentViewController] displaySnapshotNotice];
}

void displaySnapshotWarning(){
    [[ViewController currentViewController] displaySnapshotWarning];
}

void removingLiberiOS(){
    [[ViewController currentViewController] removingLiberiOS];
}

void removingElectraBeta(){
    [[ViewController currentViewController] removingElectraBeta];
}

void installingCydia(){
    [[ViewController currentViewController] installingCydia];
}

void cydiaDone(){
    [[ViewController currentViewController] cydiaDone];
}

void blockSaurikRepo(){
    NSString *hostsFile = [NSString stringWithContentsOfFile:@"/etc/hosts" encoding:NSUTF8StringEncoding error:nil];
    if ([hostsFile rangeOfString:@"\n0.0.0.0    apt.saurik.com\n"].location == NSNotFound){
        FILE *file = fopen("/etc/hosts","a");
        fprintf(file, "0.0.0.0    apt.saurik.com\n");
        fclose(file);
        
        pid_t pd;
        
        posix_spawn(&pd, "/bin/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/mobile/Library/Caches/com.saurik.Cydia", NULL }, NULL);
        waitpid(pd, NULL, 0);
        
        NSLog(@"Telesphoreo repo blocked successfully");
    }
}
