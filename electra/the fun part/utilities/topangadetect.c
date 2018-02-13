//
//  topangadetect.c
//  electra
//
//  Created by CoolStar on 2/12/18.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "topangadetect.h"
#include "file_utils.h"

bool topangaInstalled(){
    if (file_exists("/bin/bash"))
        return true;
    if (file_exists("/bin/cat"))
        return true;
    if (file_exists("/bin/cp"))
        return true;
    if (file_exists("/bin/grep"))
        return true;
    if (file_exists("/bin/uname"))
        return true;
    if (file_exists("/Library/LaunchDaemons/0.reload.plist"))
        return true;
    if (file_exists("/Library/LaunchDaemons/dropbear.plist"))
        return true;
    if (file_exists("/usr/bin/uicache"))
        return true;
    if (file_exists("/usr/bin/uiduid"))
        return true;
    if (file_exists("/usr/lib/libapt-inst.dylib"))
        return true;
    if (file_exists("/usr/lib/apt/methods/http"))
        return true;
    if (file_exists("/usr/lib/apt"))
        return true;
    if (file_exists("/usr/libexec/cydia/cydo"))
        return true;
    if (file_exists("/usr/libexec/reload"))
        return true;
    if (file_exists("/usr/sbin/iostat"))
        return true;
    return false;
}
