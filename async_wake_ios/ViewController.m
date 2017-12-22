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
  // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
  printf("******* received memory warning! ***********\n");
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

- (IBAction)doit:(id)sender {
    mach_port_t user_client;
    mach_port_t tfp0 = get_tfp0(&user_client);
    
    let_the_fun_begin(tfp0, user_client);
    
    NSLog(@" ♫ KPP never bothered me anyway... ♫ ");
    
    UIAlertController *dropbearRunning = [UIAlertController alertControllerWithTitle:@"DropBear Running" message:@"DropBear is now running! Enjoy." preferredStyle:UIAlertControllerStyleAlert];
    [dropbearRunning addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
        [dropbearRunning dismissViewControllerAnimated:YES completion:nil];
    }]];
    [self presentViewController:dropbearRunning animated:YES completion:nil];
}

- (IBAction)exit:(id)sender {
    exit(0);
    
}

@end
