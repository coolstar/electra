//
//  bootstrap.h
//  electra
//
//  Created by Jamie Bishop on 11/02/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#ifndef bootstrap_h
#define bootstrap_h

#include <stdbool.h>
#include <stdio.h>

void copy_basebinaries(void);
void extract_bootstrap(void);
void post_bootstrap(const bool runUICache);

#endif /* bootstrap_h */
