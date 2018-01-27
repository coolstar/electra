#import "ViewController.h"
#include "async_wake.h"
#include "fun.h"
#include "codesign.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)checkVersion {
    NSString *rawgitHistory = [NSString stringWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"githistory" ofType:@"txt"] encoding:NSUTF8StringEncoding error:nil];
    __block NSArray *gitHistory = [rawgitHistory componentsSeparatedByString:@"\n"];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0ul), ^{
        NSData *data = [NSData dataWithContentsOfURL:[NSURL URLWithString:@"https://coolstar.org/electra/gitlatest.txt"]];
        // User isn't on a network, or the request failed
        if (data == nil) return;
        
        NSString *gitCommit = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        
        if (![gitHistory containsObject:gitCommit]){
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Update Available!" message:@"An update for Electra is available! Please visit https://coolstar.org/electra/ on a computer to download the latest IPA!" preferredStyle:UIAlertControllerStyleAlert];
                [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
                [self presentViewController:alertController animated:YES completion:nil];
            });
        }
    });
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self checkVersion];
    
    NSNotificationCenter* notificationCenter = [NSNotificationCenter defaultCenter];
    
    BOOL enable3DTouch = YES;
    
    if (kCFCoreFoundationVersionNumber < 1443 || kCFCoreFoundationVersionNumber > 1445.32){
        [jailbreak setEnabled:NO];
        [enableTweaks setEnabled:NO];
        [jailbreak setTitle:@"Version Error" forState:UIControlStateNormal];
        
        enable3DTouch = NO;
    }
    
    uint32_t flags;
    csops(getpid(), CS_OPS_STATUS, &flags, 0);
    
    if ((flags & CS_PLATFORM_BINARY)){
        [jailbreak setEnabled:NO];
        [enableTweaks setEnabled:NO];
        [jailbreak setTitle:@"Already Jailbroken" forState:UIControlStateNormal];
        
        enable3DTouch = NO;
    }
    
    if (enable3DTouch){
        [notificationCenter addObserver:self selector:@selector(doit:) name:@"Jailbreak" object:nil];
    }
  // Do any additional setup after loading the view, typically from a nib.
}

- (IBAction)credits:(id)sender {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Credits" message:@"Electra is brought to you by CoolStar, Ian Beer, theninjaprawn, stek29, Siguza and xerub.\n\nElectra includes the following software:\namfid patch by theninjaprawn\njailbreakd & tweak injection by CoolStar\nunlocknvram & sandbox fixes by stek29\nlibsubstitute by comex\nContains code from simject by angelXwind\nAnemone by CoolStar, kirb, isklikas and goeo\nPreferenceLoader by DHowett & rpetrich" preferredStyle:UIAlertControllerStyleAlert];
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

- (IBAction)doit:(id)sender {
    [jailbreak setEnabled:NO];
    [enableTweaks setEnabled:NO];
    
    [jailbreak setTitle:@"Please Wait (1/3)" forState:UIControlStateNormal];
    
    BOOL shouldEnableTweaks = [enableTweaks isOn];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        mach_port_t user_client;
        mach_port_t tfp0 = get_tfp0(&user_client);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [jailbreak setTitle:@"Please Wait (2/3)" forState:UIControlStateNormal];
        });
        
        if (begin_fun(tfp0, user_client, shouldEnableTweaks) == 0){
            dispatch_async(dispatch_get_main_queue(), ^{
                [jailbreak setTitle:@"Jailbroken" forState:UIControlStateNormal];
                
                UIAlertController *dropbearRunning = [UIAlertController alertControllerWithTitle:@"Dropbear Running" message:@"Dropbear is now running! Enjoy." preferredStyle:UIAlertControllerStyleAlert];
                [dropbearRunning addAction:[UIAlertAction actionWithTitle:@"Exit" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                    [dropbearRunning dismissViewControllerAnimated:YES completion:nil];
                    exit(0);
                }]];
                [self presentViewController:dropbearRunning animated:YES completion:nil];
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                [jailbreak setTitle:@"Error Jailbreaking" forState:UIControlStateNormal];
            });
        }
        
        NSLog(@" ♫ KPP never bothered me anyway... ♫ ");
    });
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
