//
//  RoundedButton.m
//  async_wake_ios
//
//  Created by CoolStar on 1/12/18.
//  Copyright © 2018 CoolStar. All rights reserved.
//

#import "RoundedButton.h"

@implementation RoundedButton

- (instancetype)initWithCoder:(NSCoder *)aDecoder {
    self = [super initWithCoder:aDecoder];
    if (self){
        self.layer.cornerRadius = 10.0f;
        self.clipsToBounds = YES;
        [self setBackgroundColor:[UIColor colorWithRed:98.0f/255.f green:159.f/255.f blue:214.f/255.f alpha:0.8]];
    }
    return self;
}

- (void)setHighlighted:(BOOL)highlighted {
    [super setHighlighted:highlighted];
    if (highlighted){
        [self setBackgroundColor:[UIColor colorWithRed:98.0f/255.f green:159.f/255.f blue:214.f/255.f alpha:0.5]];
    } else {
        [self setBackgroundColor:[UIColor colorWithRed:98.0f/255.f green:159.f/255.f blue:214.f/255.f alpha:0.8]];
    }
}

/*
// Only override drawRect: if you perform custom drawing.
// An empty implementation adversely affects performance during animation.
- (void)drawRect:(CGRect)rect {
    // Drawing code
}
*/

@end
