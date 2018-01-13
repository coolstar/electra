#import "ViewController.h"
#include "async_wake.h"
#include "fun.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
    
    if (kCFCoreFoundationVersionNumber < 1443 || kCFCoreFoundationVersionNumber > 1445.32){
        [jailbreak setEnabled:NO];
        [enableTweaks setEnabled:NO];
        [jailbreak setTitle:@"Version Error" forState:UIControlStateNormal];
    }
  // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
  printf("******* received memory warning! ***********\n");
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

- (IBAction)credits:(id)sender {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Credits" message:@"Electra is brought to you by CoolStar, Ian Beer, theninjaprawn, stek29 and xerub.\n\nElectra includes the following software:\namfid patch by theninjaprawn\njailbreakd & tweak injection by CoolStar\nunlocknvram by stek29\nlibsubstitute by comex\nContains code from simject by angelXwind\nAnemone by CoolStar, kirb, isklikas and goeo\nPreferenceLoader by DHowett & rpetrich" preferredStyle:UIAlertControllerStyleAlert];
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

- (IBAction)doit:(id)sender {
    [jailbreak setEnabled:NO];
    [enableTweaks setEnabled:NO];
    
    [jailbreak setTitle:@"Please Wait" forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        mach_port_t user_client;
        mach_port_t tfp0 = get_tfp0(&user_client);
        
        if (let_the_fun_begin(tfp0, user_client, [enableTweaks isOn]) == 0){
            [jailbreak setTitle:@"Jailbroken" forState:UIControlStateNormal];
            
            UIAlertController *dropbearRunning = [UIAlertController alertControllerWithTitle:@"DropBear Running" message:@"DropBear is now running! Enjoy." preferredStyle:UIAlertControllerStyleAlert];
            [dropbearRunning addAction:[UIAlertAction actionWithTitle:@"Exit" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                [dropbearRunning dismissViewControllerAnimated:YES completion:nil];
                exit(0);
            }]];
            [self presentViewController:dropbearRunning animated:YES completion:nil];
        } else {
            [jailbreak setTitle:@"Jailbroken" forState:UIControlStateNormal];
        }
        
        NSLog(@" ♫ KPP never bothered me anyway... ♫ ");
    });
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

@end
