//
//  jailbreakd.h
//  jailbreakd message types and exported functions
//

#ifndef JAILBREAKD_H
#define JAILBREAKD_H

#include <mach/mach.h>
#include <xpc/xpc.h>

// Message IDs for XPC communication between jailbreakd and launchdhook
typedef enum {
    JBD_MSG_TEST_CALL             = 0,
    JBD_MSG_SPINLOCK_FIX_ONLY     = 1,
    JBD_MSG_SPAWN_PATCH_CHILD     = 2,
    JBD_MSG_SPAWN_EXEC_START      = 3,
    JBD_MSG_SPAWN_EXEC_CANCEL     = 4,
    JBD_MSG_EXEC_TRACE_START      = 5,
    JBD_MSG_EXEC_TRACE_CANCEL     = 6,
} JBD_MESSAGE_ID;

// Check in - returns server port from launchdhook
extern mach_port_t jailbreakdServerPort(void);

// Spawn exec patch management
extern int spawnExecPatchAdd(pid_t pid, bool resume);
extern int spawnExecPatchRemove(pid_t pid);

#endif /* JAILBREAKD_H */
