//
//  file_utils.h
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#ifndef file_utils_h
#define file_utils_h

#include <stdio.h>

int file_exists(const char *filename);
int cp(const char *to, const char *from);

#endif /* file_utils_h */
