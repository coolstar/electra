# Getting started with electra (for developers)

Electra is an iOS 11 jailbreak for versions up to, and including, iOS 11.1.2.

---

# Table of Contents
1. [Introduction](#introduction)
2. [Major changes in electra](#major-changes-in-electra)
    * [Using substitute](#using-substitute)
    * [jailbreakd](#jailbreakd)
3. [Getting development support](#getting-development-support)

# Introduction

Electra does things differently to most traditional jailbreaks, and the core of the jailbreak is based around a daemon called **jailbreakd**.

# Major changes in electra

* Substitute is used as the hooking framework instead of substrate
    * Please report issues at [the electra issues page](https://github.com/coolstar/electra/issues) and we'll look into them
* `setuid(0);` does not work out of the box (see below for how to use jailbreakd to patch setuid)
* `platform-application` **WILL NOT** platformize your binary out of the box on electra

## Using substitute

We provide a substrate-shim compatability layer, that works for *most* tweaks. Please report issues you have at [the electra issues page](https://github.com/coolstar/electra/issues) and we'll look into them.

## jailbreakd

Electra is a KPPLess jailbreak; this means that by nature, electra is not able to patch the kernel, therefore a jailbreak daemon is used in places where kernel patches would be. jailbreakd is a daemon that handles patching setuid for processes, platformising them, and handing certain entiltements out. 

We provide a libjailbreak.dylib for interfacing with jailbreakd, and this is in `/usr/lib/libjailbreak.dylib`.
All patches here will require `dlopen()`-ing the dylib, finding the appropiate symbol, and calling the respective function.

### Setting uid 0

Here is sample code to patch setuid() with electra.

```c
void patch_setuid() {
    void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
    if (!handle) 
        return;

    // Reset errors
    dlerror();
    typedef void (*fix_setuid_prt_t)(pid_t pid);
    fix_setuid_prt_t ptr = (fix_setuid_prt_t)dlsym(handle, "jb_oneshot_fix_setuid_now");
    
    const char *dlsym_error = dlerror();
    if (dlsym_error) 
        return;

    ptr(getpid());
}
```

This code is used in [our cydia fork](https://github.com/ElectraJailbreak/cydia/blob/master/cydo.cpp#L44), and has been confirmed working. The code will call libjailbreakd, which will tell jailbreakd to patch setuid for our process. `setuid(0);` can now be called normally.

### Platformizing a binary

In addition to signing your binary with the `platform-application` entiltement using ldid, you will also need to call jailbreakd to ensure your binary is correctly platformized. Sample code for this can be found below:

```c
/* Set platform binary flag */
#define FLAG_PLATFORMIZE (1 << 1)

void platformize_me() {
    void* handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_LAZY);
    if (!handle) return;
    
    // Reset errors
    dlerror();
    typedef void (*fix_entitle_prt_t)(pid_t pid, uint32_t what);
    fix_entitle_prt_t ptr = (fix_entitle_prt_t)dlsym(handle, "jb_oneshot_entitle_now");
    
    const char *dlsym_error = dlerror();
    if (dlsym_error) return;
    
    ptr(getpid(), FLAG_PLATFORMIZE);
}
```

# Getting development support

* Join the /r/jailbreak [discord](https://discord.gg/jb), and ask for help in #development
* Create a post on /r/jailbreakdevelopers
* If neither of these solve your issues, open an issue on the [the electra issues page](https://github.com/coolstar/electra/issues)
