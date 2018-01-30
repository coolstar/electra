#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#import <xpc/xpc.h>

int main(int argc, char **argv, char **envp) {
    if (argc < 3){
        printf("Usage: \n");
        printf("jailbreakd_client <pid> <1 | 2 | 6>\n");
        printf("\t1 = entitle+platformize the target PID\n");
        printf("\t2 = entitle+platformize the target PID and subsequently sent SIGCONT\n");
        printf("\t6 = fixup setuid in the target PID\n");
        return 0;
    }
    if (atoi(argv[2]) != 1 && atoi(argv[2]) != 2 && atoi(argv[2]) != 6){
        printf("Usage: \n");
        printf("jailbreakd_client <pid> <1 | 2 | 6>\n");
        printf("\t1 = entitle the target PID\n");
        printf("\t2 = entitle+platformize the target PID and subsequently sent SIGCONT\n");
        printf("\t6 = fixup setuid in the target PID\n");
        return 0;
    }

    xpc_connection_t connection = xpc_connection_create_mach_service("org.coolstar.electra.jailbreakd.xpc", NULL, 0);
    xpc_connection_set_event_handler(connection, ^(xpc_object_t object) {
        char *desc = xpc_copy_description(object);
        printf("event handler: %s\n",  desc);
        free(desc);
    });
    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);

    int arg = atoi(argv[2]);
    if (arg == 1) {
        xpc_dictionary_set_string(message, "action", "entp");
        xpc_dictionary_set_uint64(message, "flags", 7);
    } else if (arg == 2) {
        xpc_dictionary_set_string(message, "action", "entp");
        xpc_dictionary_set_uint64(message, "flags", 15);
    } else if (arg == 6) {
        xpc_dictionary_set_string(message, "action", "suid");
    }

    xpc_dictionary_set_int64(message, "pid", atoi(argv[1]));

    dispatch_async(dispatch_get_main_queue(), ^{
        xpc_object_t reply = xpc_connection_send_message_with_reply_sync(connection, message);
        char *desc = xpc_copy_description(reply);
        printf("done: %s\n",  desc);
        free(desc);

        xpc_release(reply);
        xpc_release(message);
        exit(0);
    });

    dispatch_main();
	return 0;
}

// vim:ft=objc
