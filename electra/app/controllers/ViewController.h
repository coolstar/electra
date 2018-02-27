#import <UIKit/UIKit.h>

@interface ViewController : UIViewController {
    IBOutlet UISwitch *enableTweaks;
    IBOutlet UIButton *jailbreak;
}
+ (instancetype)currentViewController;
- (void)removingLiberiOS;
- (void)removingElectraBeta;
- (void)installingCydia;
- (void)cydiaDone;
- (void)displaySnapshotNotice;
- (void)displaySnapshotWarning;
@end

