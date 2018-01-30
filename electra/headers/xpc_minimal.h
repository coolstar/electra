//
//  xpc_minimal.h
//  electra
//
//  Created by karin on 29/1/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#ifndef xpc_minimal_h
#define xpc_minimal_h

/* Minimal header for fun.c */

typedef void *xpc_object_t;
typedef xpc_object_t xpc_connection_t;

xpc_connection_t xpc_connection_create_mach_service(const char *, dispatch_queue_t, uint64_t);
void xpc_connection_set_event_handler(xpc_connection_t, void (^)(xpc_object_t));
void xpc_connection_resume(xpc_connection_t);

xpc_object_t xpc_dictionary_create(const char **, const xpc_object_t *, size_t);
void xpc_dictionary_set_string(xpc_object_t, const char *, const char *);

xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t, xpc_object_t);
// jailbreakd is alive past this point
void xpc_connection_cancel(xpc_connection_t);

char *xpc_copy_description(xpc_object_t);

#endif /* xpc_minimal_h */
