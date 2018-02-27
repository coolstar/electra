//
//  fun_objc.h
//  async_wake_ios
//
//  Created by George on 16/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef fun_objc_h
#define fun_objc_h

const char* progname(const char*);;
void extractGz(const char *from, const char *to);
void update_springboard_plist(void);
void startDaemons(void);
void displaySnapshotWarning(void);
void displaySnapshotNotice(void);

void removingLiberiOS(void);
void removingElectraBeta(void);
void installingCydia(void);
void cydiaDone(void);

void blockSaurikRepo(void);
#endif /* fun_objc_h */
