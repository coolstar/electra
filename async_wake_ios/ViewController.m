#import "ViewController.h"
#include <stdio.h>
#include "kmem.h"

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

- (IBAction)panic:(id)sender {
	for (int i = 0; i<0xff; i++) {
		rk64(0xFFFFFFF007004000 + i*0x100000);
	}
}

@end
