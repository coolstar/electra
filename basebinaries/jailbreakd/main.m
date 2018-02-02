#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import <os/log.h>
#include "kexecute.h"
#include "kern_utils.h"
#include "patchfinder64.h"

#define PROC_PIDPATHINFO_MAXSIZE  (4*MAXPATHLEN)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

int remove_memory_limit(void) {
    // daemons run under launchd have a very stingy memory limit by default, we need
    // quite a bit more for patchfinder so disable it here
    // (note that we need the com.apple.private.memorystatus entitlement to do so)
    pid_t my_pid = getpid();
    return memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, my_pid, 0, NULL, 0);
}

mach_port_t tfpzero;
uint64_t kernel_base;
uint64_t kernel_slide;
extern unsigned offsetof_ip_kobject;

/*
    The jailbreakd XPC protocol request:
    {
        "action": string, see below
        "pid": int64
        "flags": uint64, see below, only for entp
    }

    The reply:
    {
        "action": string from request
        "pid": int64 from request
        "result": uint64, 1 for success or 0 for failure
    }

    Bugs:
    - the exit command doesn't reply
    - failure currently isn't implemented so result is always 1
*/

const char *JAILBREAKD_ACTION_ENTITLE = "entp";
const char *JAILBREAKD_ACTION_FIX_SETUID = "suid";
const char *JAILBREAKD_ACTION_PING = "ping";
const char *JAILBREAKD_ACTION_EXIT = "exit";

/* Flags for entp command. Any combination or none can be specified. */
/* Wait for xpcproxy to exec before continuing */
#define FLAG_WAIT_EXEC   (1 << 5)
/* Wait for 0.5 sec after acting */
#define FLAG_DELAY       (1 << 4)
/* Send SIGCONT after acting */
#define FLAG_SIGCONT     (1 << 3)
/* Set sandbox exception */
#define FLAG_SANDBOX     (1 << 2)
/* Set platform binary flag */
#define FLAG_PLATFORMIZE (1 << 1)
/* Set basic entitlements */
#define FLAG_ENTITLE     (1)

/* bits 0-3 */
#define FLAG_KERN_ACTIONS_MASK (0x07)
#define FLAG_WAITING_MASK (0x30)

/* Convert the bitset specified above to a string like "eps--X" */
static void flags_to_string(uint64_t flags, char *flgstr) {
    const char *set = "epsCDX";
    for (int i = 0; i < 6; ++i) {
        if (flags & (1 << i)) {
            flgstr[i] = set[i];
        } else {
            flgstr[i] = '-';
        }
    }
}

static void do_entp_stuff_with_pid(uint64_t stuff, pid_t pid, void(^finish)(uint64_t stuff, pid_t pid)) {
    void (^actually_do_what_were_supposed_to)(void) = ^{
        /* FIXME: respect flags */
        setcsflagsandplatformize(pid);

        if (stuff & FLAG_SIGCONT) {
            kill(pid, SIGCONT);
        }

        /* see below! */
        if ((stuff & FLAG_WAIT_EXEC) == 0) {
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                finish(stuff, pid);
            });
        }
    };

    /* skip waitgroup nonsense if we can */
    if ((stuff & FLAG_WAITING_MASK) == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            actually_do_what_were_supposed_to();
        });
        return;
    }

    /* we'll wait on both conditions at the same time */
    dispatch_group_t waitgroup = dispatch_group_create();
    if (stuff & FLAG_WAIT_EXEC) {
        /* it's safe to get xpcproxy's path here --
           pspawn_payload won't exec until later */
        // char *cmp_path = malloc(PROC_PIDPATHINFO_MAXSIZE);
        // memset(cmp_path, 0, PROC_PIDPATHINFO_MAXSIZE);
        // proc_pidpath(pid, cmp_path, PROC_PIDPATHINFO_MAXSIZE);

        dispatch_group_async(waitgroup, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};
            int32_t timeout = 1000000;

            NSLog(@"Waiting to ensure it's not xpcproxy anymore...");
            int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
            while (timeout > 0 && ret > 0 && strcmp(pathbuf, "/usr/libexec/xpcproxy") == 0){
                proc_pidpath(pid, pathbuf, sizeof(pathbuf));
                timeout -= 100;
                usleep(100);
            }

            if (timeout <= 0) {
                NSLog(@"Warning! exited because of timeout!");
            }
            // free(cmp_path);
        });

        /* hack: the pspawn payload won't exec until we reply, so just for
           FLAG_XPCPROXY, we'll pretend the operation completed before it actually does */
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            finish(stuff, pid);
        });
    }

    if (stuff & FLAG_DELAY) {
        dispatch_group_enter(waitgroup);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            dispatch_group_leave(waitgroup);
        });
    }

    dispatch_group_notify(waitgroup, dispatch_get_main_queue(), actually_do_what_were_supposed_to);
    dispatch_release(waitgroup);
}

static void do_suid_with_pid(pid_t pid, void(^finish)(pid_t pid)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        fixupsetuid(pid);
        finish(pid);
    });
}

static void jailbreakd_handle_xpc_connection(xpc_connection_t who) {
    xpc_connection_set_event_handler(who, ^(xpc_object_t msg) {
        xpc_type_t type = xpc_get_type(msg);
        if (type == XPC_TYPE_ERROR) {
            NSLog(@"jailbreakd: connection error %s", xpc_dictionary_get_string(msg, XPC_ERROR_KEY_DESCRIPTION));
            return;
        }

        xpc_connection_t peer = xpc_dictionary_get_remote_connection(msg);

        char *desc = xpc_copy_description(msg);
        NSLog(@"jailbreakd: received object: %s", desc);
        free(desc);

        const char *action = xpc_dictionary_get_string(msg, "action");
        if (!action) {
            char *desc = xpc_copy_description(msg);
            NSLog(@"jailbreakd: received message from pid %d with no action: %s",
                xpc_connection_get_pid(peer),
                desc);
            free(desc);
            xpc_connection_cancel(peer);
            return;
        }

        // TODO: use csops to restrict custom pid to entitlement?
        pid_t reqpid = (pid_t)xpc_dictionary_get_int64(msg, "pid");
        if (reqpid == 0) {
            reqpid = xpc_connection_get_pid(peer);
        }

        xpc_retain(msg);
        if (!strcmp(action, JAILBREAKD_ACTION_ENTITLE)) {
            uint64_t flags = xpc_dictionary_get_uint64(msg, "flags");
            do_entp_stuff_with_pid(flags, reqpid, ^(uint64_t stuff, pid_t pid) {
                char flgstr[7] = {0};
                flags_to_string(flags, flgstr);
                NSLog(@"jailbreakd: entitle operations: %s complete for pid %d", flgstr, reqpid);

                xpc_object_t reply = xpc_dictionary_create_reply(msg);
                if (!reply) {
                    NSLog(@"jailbreakd: can't create reply. did the other end hang up too soon??");
                    xpc_release(msg);
                    return;
                }

                xpc_dictionary_set_string(reply, "action", action);
                xpc_dictionary_set_uint64(reply, "flags", flags);
                xpc_dictionary_set_uint64(reply, "result", 1);

                xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
                xpc_release(reply);
                xpc_release(msg);
            });
        } else if (!strcmp(action, JAILBREAKD_ACTION_FIX_SETUID)) {
            do_suid_with_pid(reqpid, ^(pid_t pid) {
                NSLog(@"jailbreakd: suid complete for pid %d", reqpid);

                xpc_object_t reply = xpc_dictionary_create_reply(msg);
                if (!reply) {
                    NSLog(@"jailbreakd: can't create reply. did the other end hang up too soon??");
                    xpc_release(msg);
                    return;
                }

                xpc_dictionary_set_string(reply, "action", action);
                xpc_dictionary_set_uint64(reply, "result", 1);

                xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
                xpc_release(reply);
                xpc_release(msg);
            });
        } else if (!strcmp(action, JAILBREAKD_ACTION_PING)) {
            NSLog(@"jailbreakd: ping complete for pid %d", reqpid);
            xpc_object_t reply = xpc_dictionary_create_reply(msg);
            if (!reply) {
                NSLog(@"jailbreakd: can't create reply. did the other end hang up too soon??");
                xpc_release(msg);
                return;
            }

            xpc_dictionary_set_string(reply, "action", action);
            xpc_dictionary_set_uint64(reply, "result", 1);

            xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
            xpc_release(reply);
            xpc_release(msg);
        } else if (!strcmp(action, JAILBREAKD_ACTION_EXIT)) {
            xpc_release(msg);

            NSLog(@"jailbreakd: exiting for pid %d!", reqpid);

            term_kexecute();
            exit(0);
        } else {
            NSLog(@"jailbreakd: invalid action! %s", action);
            xpc_release(msg);
            xpc_connection_cancel(peer);
        }
    });
    xpc_connection_resume(who);
}

int main(int argc, char **argv, char **envp) {
    NSLog(@"jailbreakd: start");

    unlink("/tmp/jailbreakd.pid");
    int fd = open("/tmp/jailbreakd.pid", O_WRONLY | O_CREAT, 0600);
    char mmmm[8] = {0};
    int sz = snprintf(mmmm, 8, "%d", getpid());
    write(fd, mmmm, sz);
    close(fd);

    NSLog(@"jailbreakd: dumped pid");

    kernel_base = strtoull(getenv("KernelBase"), NULL, 16);
    remove_memory_limit();

    kern_return_t err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfpzero);
    if (err != KERN_SUCCESS) {
        NSLog(@"host_get_special_port 4: %s", mach_error_string(err));
        return 5;
    }

    init_kernel(kernel_base, NULL);
    // Get the slide
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    NSLog(@"jailbreakd: slide: 0x%016llx", kernel_slide);
    init_kexecute();

    @autoreleasepool {
        /* About concurrency:
             kernel calls run on the main thread ONLY. Everything else can run in dispatch global queues. */
        xpc_connection_t connection = xpc_connection_create_mach_service(
            "com.apple.uikit.viewservice.xxx.dainsleif.xpc",
            NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
        if (!connection) {
            NSLog(@"jailbreakd: no XPC service");
            return 0;
        }

        // Configure event handler
        xpc_connection_set_event_handler(connection, ^(xpc_object_t object) {
            xpc_type_t type = xpc_get_type(object);
            if (type == XPC_TYPE_CONNECTION) {
                NSLog(@"jailbreakd: received XPC connection!");
                jailbreakd_handle_xpc_connection(object);
            } else if (type == XPC_TYPE_ERROR) {
                NSLog(@"jailbreakd: XPC error in listener: %s", xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION));
            }
        });

        // Make connection live
        xpc_connection_resume(connection);
        NSLog(@"it never fails to strike its target, and the wounds it causes do not heal");
        NSLog(@"in other words, XPC is online");

        dispatch_main();
    }

    return EXIT_FAILURE;
}
