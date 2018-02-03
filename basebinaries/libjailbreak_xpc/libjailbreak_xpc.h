#include <sys/types.h>
#include <stdint.h>

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

typedef void *jb_connection_t;

#if __BLOCKS__
typedef void (^jb_callback_t)(int result);

/* These ones run asynchronously. Callbacks take 1 on success, 0 on failure.
   The queue which they run on is undefined. */
extern void jb_entitle(jb_connection_t connection, pid_t pid, uint32_t what, jb_callback_t done);
extern void jb_fix_setuid(jb_connection_t connection, pid_t pid, jb_callback_t done);
#endif

extern jb_connection_t jb_connect(void);
extern void jb_disconnect(jb_connection_t connection);

extern int jb_entitle_now(jb_connection_t connection, pid_t pid, uint32_t what);
extern int jb_fix_setuid_now(jb_connection_t connection, pid_t pid);

extern void jb_oneshot_entitle_now(pid_t pid, uint32_t what);
extern void jb_oneshot_fix_setuid_now(pid_t pid);
