//
//  apfs_util.h
//  electra
//
//  Created by CoolStar on 2/26/18.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#ifndef apfs_util_h
#define apfs_util_h

int list_snapshots(const char *vol);
int check_snapshot(const char *vol, const char *snap);

#endif /* apfs_util_h */
