//
//  CSGradientSeparatorView.m
//  async_wake_ios
//
//  Created by CoolStar on 1/12/18.
//  Copyright © 2018 CoolStar. All rights reserved.
//

#import "CSGradientSeparatorView.h"

@implementation CSGradientSeparatorView

- (instancetype)initWithCoder:(NSCoder *)aDecoder {
    self = [super initWithCoder:aDecoder];
    if (self){
        [self setBackgroundColor:[UIColor clearColor]];
        
        CAGradientLayer *layer = (CAGradientLayer *)self.layer;
        layer.startPoint = CGPointMake(0, 0.5);
        layer.endPoint = CGPointMake(1, 0.5);
        layer.colors = @[(id)[[UIColor colorWithWhite:0.0f alpha:0] CGColor], (id)[[UIColor colorWithWhite:0.0f alpha:0.3f] CGColor], (id)[[UIColor colorWithWhite:0.0f alpha:0] CGColor]];
        layer.locations = @[@0, @0.5, @1];
    }
    return self;
}

+ (Class)layerClass {
    return [CAGradientLayer class];
}
/*
// Only override drawRect: if you perform custom drawing.
// An empty implementation adversely affects performance during animation.
- (void)drawRect:(CGRect)rect {
    // Drawing code
}
*/

@end
