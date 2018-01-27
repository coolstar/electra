#import <Foundation/Foundation.h>
#import "kern_utils.h"
#import "kmem.h"
#import "patchfinder64.h"
#import "kexecute.h"
#import "offsetof.h"
#import "osobject.h"
#import "sandbox.h"

#define TF_PLATFORM 0x400

#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */
#define CS_ENTITLEMENTS_VALIDATED	0x0004000

#define	CS_ALLOWED_MACHO	0x00ffffe

#define CS_EXEC_SET_HARD	0x0100000	/* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL	0x0200000	/* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT	0x0400000	/* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER	0x0800000	/* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED		0x1000000	/* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM	0x2000000	/* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY	0x4000000	/* this is a platform binary */
#define CS_PLATFORM_PATH	0x8000000	/* platform binary by the fact of path (osx only) */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
#define CS_SIGNED         0x20000000  /* process has a signature (may have gone invalid) */
#define CS_DEV_CODE         0x40000000  /* code is dev signed, cannot be loaded into prod signed code (will go away with rdar://problem/28322552) */

uint64_t proc_find(int pd, int tries) {
  // TODO use kcall(proc_find) + ZM_FIX_ADDR
  while (tries-- > 0) {
    uint64_t proc = rk64(find_allproc());
    while (proc) {
      uint32_t pid = rk32(proc + offsetof_p_pid);
      if (pid == pd) {
        return proc;
      }
      proc = rk64(proc);
    }
  }
  return 0;
}

CACHED_FIND(uint64_t, our_task_addr) {
  uint64_t our_proc = proc_find(getpid(), 1);

  if (our_proc == 0) {
    printf("failed to find our_task_addr!\n");
    exit(EXIT_FAILURE);
  }

  uint64_t addr = rk64(our_proc + offsetof_task);
  printf("our_task_addr: 0x%llx\n", addr);
  return addr;
}

uint64_t find_port(mach_port_name_t port){
  uint64_t task_addr = our_task_addr();
  
  uint64_t itk_space = rk64(task_addr + offsetof_itk_space);
  
  uint64_t is_table = rk64(itk_space + offsetof_ipc_space_is_table);
  
  uint32_t port_index = port >> 8;
  const int sizeof_ipc_entry_t = 0x18;
  
  uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));
  return port_addr;
}

int dumppid(int pd){
  uint64_t proc = proc_find(pd, 3);
  if (proc != 0) {
    uid_t p_uid = rk32(proc + offsetof_p_uid);
    gid_t p_gid = rk32(proc + offsetof_p_gid);
    uid_t p_ruid = rk32(proc + offsetof_p_ruid);
    gid_t p_rgid = rk32(proc + offsetof_p_rgid);

    uint64_t ucred = rk64(proc + offsetof_p_ucred);
    uid_t cr_uid = rk32(ucred + offsetof_ucred_cr_uid);
    uid_t cr_ruid = rk32(ucred + offsetof_ucred_cr_ruid);
    uid_t cr_svuid = rk32(ucred + offsetof_ucred_cr_svuid);

    NSLog(@"Found PID %d", pd);
    NSLog(@"UID: %d GID: %d RUID: %d RGID: %d", p_uid, p_gid, p_ruid, p_rgid);
    NSLog(@"CR_UID: %d CR_RUID: %d CR_SVUID: %d", cr_uid, cr_ruid, cr_svuid);
    return 0;
  } else {
    return 1;
  }
}

void set_csflags(uint64_t proc) {
    uint32_t csflags = rk32(proc + offsetof_p_csflags);
#ifdef JAILBREAKDDEBUG
    NSLog(@"Previous CSFlags: 0x%x", csflags);
#endif
    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
#ifdef JAILBREAKDDEBUG
    NSLog(@"New CSFlags: 0x%x", csflags);
#endif
    wk32(proc + offsetof_p_csflags, csflags);
}

void set_tfplatform(uint64_t proc) {
    // task.t_flags & TF_PLATFORM
    uint64_t task = rk64(proc + offsetof_task);
    uint32_t t_flags = rk32(task + offsetof_t_flags);
#ifdef JAILBREAKDDEBUG
    NSLog(@"Old t_flags: 0x%x", t_flags);
#endif
    t_flags |= TF_PLATFORM;
    wk32(task+offsetof_t_flags, t_flags);
#ifdef JAILBREAKDDEBUG
    NSLog(@"New t_flags: 0x%x", t_flags);
#endif
}

void set_csblob(uint64_t proc) {
    uint64_t textvp = rk64(proc + offsetof_p_textvp); //vnode of executable
    off_t textoff = rk64(proc + offsetof_p_textoff);
    
#ifdef JAILBREAKDDEBUG
    NSLog(@"\t__TEXT at 0x%llx. Offset: 0x%llx", textvp, textoff);
#endif
    if (textvp != 0){
      uint32_t vnode_type_tag = rk32(textvp + offsetof_v_type);
      uint16_t vnode_type = vnode_type_tag & 0xffff;
      uint16_t vnode_tag = (vnode_type_tag >> 16);
#ifdef JAILBREAKDDEBUG
      NSLog(@"\tVNode Type: 0x%x. Tag: 0x%x.", vnode_type, vnode_tag);
#endif
      
      if (vnode_type == 1){
          uint64_t ubcinfo = rk64(textvp + offsetof_v_ubcinfo);
#ifdef JAILBREAKDDEBUG
          NSLog(@"\t\tUBCInfo at 0x%llx.\n", ubcinfo);
#endif
          
          uint64_t csblobs = rk64(ubcinfo + offsetof_ubcinfo_csblobs);
          while (csblobs != 0){
#ifdef JAILBREAKDDEBUG
              NSLog(@"\t\t\tCSBlobs at 0x%llx.", csblobs);
#endif
              
              cpu_type_t csblob_cputype = rk32(csblobs + offsetof_csb_cputype);
              unsigned int csblob_flags = rk32(csblobs + offsetof_csb_flags);
              off_t csb_base_offset = rk64(csblobs + offsetof_csb_base_offset);
              uint64_t csb_entitlements = rk64(csblobs + offsetof_csb_entitlements_offset);
              unsigned int csb_signer_type = rk32(csblobs + offsetof_csb_signer_type);
              unsigned int csb_platform_binary = rk32(csblobs + offsetof_csb_platform_binary);
              unsigned int csb_platform_path = rk32(csblobs + offsetof_csb_platform_path);

#ifdef JAILBREAKDDEBUG
              NSLog(@"\t\t\tCSBlob CPU Type: 0x%x. Flags: 0x%x. Offset: 0x%llx", csblob_cputype, csblob_flags, csb_base_offset);
              NSLog(@"\t\t\tCSBlob Signer Type: 0x%x. Platform Binary: %d Path: %d", csb_signer_type, csb_platform_binary, csb_platform_path);
#endif
              wk32(csblobs + offsetof_csb_platform_binary, 1);

              csb_platform_binary = rk32(csblobs + offsetof_csb_platform_binary);
#ifdef JAILBREAKDDEBUG
              NSLog(@"\t\t\tCSBlob Signer Type: 0x%x. Platform Binary: %d Path: %d", csb_signer_type, csb_platform_binary, csb_platform_path);
              
              NSLog(@"\t\t\t\tEntitlements at 0x%llx.\n", csb_entitlements);
#endif
              csblobs = rk64(csblobs);
          }
      }
    }
}

const char* abs_path_exceptions[] = {
  "/bootstrap",
  "/Library",
  // XXX there's some weird stuff about linking and special
  // handling for /private/var/mobile/* in sandbox
  "/private/var/mobile/Library",
  NULL
};

uint64_t get_exception_osarray(void) {
  static uint64_t cached = 0;

  if (cached == 0) {
    // XXX use abs_path_exceptions
    cached = OSUnserializeXML("<array>"
    "<string>/bootstrap/</string>"
    "<string>/Library/</string>"
    "<string>/private/var/mobile/Library/</string>"
    "</array>");
  }

  return cached;
}

static const char *exc_key = "com.apple.security.exception.files.absolute-path.read-only";

void set_sandbox_extensions(uint64_t proc) {
  uint64_t proc_ucred = rk64(proc+0x100);
  uint64_t sandbox = rk64(rk64(proc_ucred+0x78) + 8 + 8);

  NSLog(@"proc = 0x%llx & proc_ucred = 0x%llx & sandbox = 0x%llx", proc, proc_ucred, sandbox);

  if (sandbox == 0) {
    NSLog(@"no sandbox, skipping");
    return;
  }

  if (has_file_extension(sandbox, abs_path_exceptions[0])) {
    NSLog(@"already has '%s', skipping", abs_path_exceptions[0]);
    return;
  }

  uint64_t ext = 0;
  const char** path = abs_path_exceptions;
  while (*path != NULL) {
    ext = extension_create_file(*path, ext);
    if (ext == 0) {
      NSLog(@"extension_create_file(%s) failed, panic!", *path);
    }
    ++path;
  }

  NSLog(@"last extension_create_file ext: 0x%llx", ext);

  if (ext != 0) {
    extension_add(ext, sandbox, exc_key);
  }
}

void set_amfi_entitlements(uint64_t proc) {
    // AMFI entitlements
#ifdef JAILBREAKDDEBUG
    NSLog(@"%@",@"AMFI:");
#endif
    uint64_t proc_ucred = rk64(proc+0x100);
    uint64_t amfi_entitlements = rk64(rk64(proc_ucred+0x78)+0x8);
#ifdef JAILBREAKDDEBUG
    NSLog(@"%@",@"Setting Entitlements...");
#endif

    OSDictionary_SetItem(amfi_entitlements, "get-task-allow", find_OSBoolean_True());
    OSDictionary_SetItem(amfi_entitlements, "com.apple.private.skip-library-validation", find_OSBoolean_True());

    uint64_t present = OSDictionary_GetItem(amfi_entitlements, exc_key);

    int rv = 0;

    if (present == 0) {
      rv = OSDictionary_SetItem(amfi_entitlements, exc_key, get_exception_osarray());
    } else if (present != get_exception_osarray()) {
        unsigned int itemCount = OSArray_ItemCount(present);
        
        NSLog(@"present != 0 (0x%llx)! item count: %d", present, itemCount);
        
        BOOL foundEntitlements = NO;
        
        uint64_t itemBuffer = OSArray_ItemBuffer(present);
        
        for (int i = 0; i < itemCount; i++){
            uint64_t item = rk64(itemBuffer + (i * sizeof(void *)));
            NSLog(@"Item %d: 0x%llx", i, item);
            char *entitlementString = OSString_CopyString(item);
            if (strcmp(entitlementString, "/bootstrap/") == 0){
                foundEntitlements = YES;
                free(entitlementString);
                break;
            }
            free(entitlementString);
        }
        
        if (!foundEntitlements){
            rv = OSArray_Merge(present, get_exception_osarray());
        } else {
            rv = 1;
        }
    } else {
      NSLog(@"Not going to merge array with itself :P");
      rv = 1;
    }

    if (rv != 1) {
      NSLog(@"Setting exc FAILED! amfi_entitlements: 0x%llx present: 0x%llx\n", amfi_entitlements, present);
    }
}

int setcsflagsandplatformize(int pid){
  uint64_t proc = proc_find(pid, 3);
  if (proc != 0) {
    set_csflags(proc);
    set_tfplatform(proc);
    set_amfi_entitlements(proc);
    set_sandbox_extensions(proc);
    set_csblob(proc);
    NSLog(@"setcsflagsandplatformize on PID %d", pid);
    return 0;
  }
  NSLog(@"Unable to find PID %d to entitle!", pid);
  return 1;
}
