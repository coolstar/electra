#include "libjailbreak_xpc.h"
#include <xpc/xpc.h>
#include <dispatch/dispatch.h>

#define FLAG_ATTRIBUTE_XPCPROXY (1 << 17)
#define FLAG_ATTRIBUTE_LAUNCHD  (1 << 16)

typedef void *jb_connection_t;

jb_connection_t jb_connect(void) {
    dispatch_queue_t private_queue = dispatch_queue_create("org.coolstar.electra.jailbreakd.client", DISPATCH_QUEUE_CONCURRENT);
    xpc_connection_t connection = xpc_connection_create_mach_service("com.apple.uikit.viewservice.xxx.dainsleif.xpc", private_queue, 0);
    xpc_connection_set_context(connection, private_queue);
    xpc_connection_set_finalizer_f(connection, (xpc_finalizer_t)dispatch_release);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t object) {
        char *desc = xpc_copy_description(object);
        printf("event: %s\n",  desc);
        free(desc);
    });
    xpc_connection_resume(connection);

    return (jb_connection_t)connection;
}

void jb_disconnect(jb_connection_t connection) {
    xpc_connection_cancel(connection);
    xpc_release(connection);
}

void jb_entitle(jb_connection_t connection, pid_t pid, uint32_t what, jb_callback_t done) {
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);

    xpc_dictionary_set_string(message, "action", "entp");
    xpc_dictionary_set_uint64(message, "flags", what);
    xpc_dictionary_set_int64(message, "pid", pid);

    if (what & FLAG_ATTRIBUTE_LAUNCHD)
        xpc_dictionary_set_string(message, "attribution", "launchd");
    if (what & FLAG_ATTRIBUTE_XPCPROXY)
        xpc_dictionary_set_string(message, "attribution", "xpcproxy");

    xpc_connection_send_message_with_reply(connection, message, NULL, ^(xpc_object_t reply) {
        if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
            int ret = (int)xpc_dictionary_get_uint64(reply, "result");
            done(ret);
        } else {
            done(0);
        }
    });

    xpc_release(message);
}

void jb_fix_setuid(jb_connection_t connection, pid_t pid, jb_callback_t done) {
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);

    xpc_dictionary_set_string(message, "action", "suid");
    xpc_dictionary_set_int64(message, "pid", pid);

    xpc_connection_send_message_with_reply(connection, message, NULL, ^(xpc_object_t reply) {
        if (xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
            int ret = (int)xpc_dictionary_get_uint64(reply, "result");
            done(ret);
        } else {
            done(0);
        }
    });

    xpc_release(message);
}

int jb_entitle_now(jb_connection_t connection, pid_t pid, uint32_t what) {
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);

    xpc_dictionary_set_string(message, "action", "entp");
    xpc_dictionary_set_uint64(message, "flags", what);
    xpc_dictionary_set_int64(message, "pid", pid);

    if (what & FLAG_ATTRIBUTE_LAUNCHD)
        xpc_dictionary_set_string(message, "attribution", "launchd");
    if (what & FLAG_ATTRIBUTE_XPCPROXY)
        xpc_dictionary_set_string(message, "attribution", "xpcproxy");

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(connection, message);
    int ret = (int)xpc_dictionary_get_uint64(reply, "result");

    xpc_release(message);
    xpc_release(reply);

    return ret;
}

int jb_fix_setuid_now(jb_connection_t connection, pid_t pid) {
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);

    xpc_dictionary_set_string(message, "action", "suid");
    xpc_dictionary_set_int64(message, "pid", pid);

    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(connection, message);
    int ret = (int)xpc_dictionary_get_uint64(reply, "result");

    xpc_release(message);
    xpc_release(reply);

    return ret;
}

void jb_oneshot_entitle_now(pid_t pid, uint32_t what) {
    jb_connection_t c = jb_connect();
    jb_entitle_now(c, pid, what);
    jb_disconnect(c);
}

void jb_oneshot_fix_setuid_now(pid_t pid) {
    jb_connection_t c = jb_connect();
    jb_fix_setuid_now(c, pid);
    jb_disconnect(c);
}
