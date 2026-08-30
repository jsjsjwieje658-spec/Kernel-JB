//
//  jailbreakd.h
//  jailbreakd message types and exported functions
//
//  Kernel-JB uses message IDs: 101, 1001-1006
//

#ifndef JAILBREAKD_H
#define JAILBREAKD_H

#include <unistd.h>

typedef enum {
    JBD_MSG_TEST_CALL = 101,
    JBD_MSG_SPAWN_PATCH_CHILD = 1001,
    JBD_MSG_SPAWN_EXEC_START = 1002,
    JBD_MSG_SPAWN_EXEC_CANCEL = 1003,
    JBD_MSG_EXEC_TRACE_START = 1004,
    JBD_MSG_EXEC_TRACE_CANCEL = 1005,
    JBD_MSG_SPINLOCK_FIX_ONLY = 1006,
} JBD_MESSAGE_ID;

#endif /* JAILBREAKD_H */
