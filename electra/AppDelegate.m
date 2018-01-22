#import "AppDelegate.h"
#include "async_wake.h"
#include "fun.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#import <CoreFoundation/CoreFoundation.h>

extern int MISValidateSignatureAndCopyInfo (CFStringRef File, CFDictionaryRef Opts, NSDictionary *Info);
extern CFStringRef MISCopyErrorStringForErrorCode(int Error);

typedef int (*t)(CFStringRef f, CFDictionaryRef o, NSDictionary**	I);
typedef CFStringRef (*w)(int e);

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    [self jailbreakShortcut];
    return YES;
}

- (void)jailbreakShortcut {
    NSMutableArray *shortcutItems = [NSMutableArray array];
    UIApplicationShortcutItem *jb =  [[UIApplicationShortcutItem alloc]initWithType:@"1" localizedTitle:@"Jailbreak"];
    [shortcutItems addObject:jb];
    [[UIApplication sharedApplication] setShortcutItems:shortcutItems];
}

- (void)application:(UIApplication *)application performActionForShortcutItem:(UIApplicationShortcutItem *)shortcutItem completionHandler:(void (^)(BOOL))completionHandler {
    switch (shortcutItem.type.integerValue) {
        case 1: {
            [[NSNotificationCenter defaultCenter] postNotificationName:@"Jailbreak" object:self userInfo:@{@"type":@"1"}];
        }   break;
    }
}

- (void)applicationWillResignActive:(UIApplication *)application {
  // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
  // Use this method to pause ongoing tasks, disable timers, and invalidate graphics rendering callbacks. Games should use this method to pause the game.
}


- (void)applicationDidEnterBackground:(UIApplication *)application {
  // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
  // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}


- (void)applicationWillEnterForeground:(UIApplication *)application {
  // Called as part of the transition from the background to the active state; here you can undo many of the changes made on entering the background.
}


- (void)applicationDidBecomeActive:(UIApplication *)application {
  // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}


- (void)applicationWillTerminate:(UIApplication *)application {
  // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}


@end
