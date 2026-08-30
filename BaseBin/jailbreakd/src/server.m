//
//  server.m
//  jailbreakd server - handles XPC messages from launchdhook
//
//  Handles process trust patching requests:
//    - JBD_MSG_SPAWN_PATCH_CHILD: patch child process trust
//    - JBD_MSG_SPAWN_EXEC_START/CANCEL: handle exec() re-trust
//    - JBD_MSG_EXEC_TRACE_START/CANCEL: ptrace-based monitoring
//    - JBD_MSG_SPINLOCK_FIX_ONLY: spinlock fix
//    - JBD_MSG_TEST_CALL: liveness check
//

#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/log.h>
#include <libjailbreak/roothider.h>

#include "jailbreakd.h"

void jailbreakd_reply_message(xpc_object_t reply) {
    int err = xpc_pipe_routine_reply(reply);
    if (err != 0) {
        JBLogError("jailbreakd: xpc_pipe_routine_reply error %d", err);
    }
}

void jailbreakd_received_message(mach_port_t port) {
    @autoreleasepool {
        xpc_object_t message = nil;
        int err = xpc_pipe_receive(port, &message);
        if (err != 0) {
            JBLogError("jailbreakd: xpc_pipe_receive error %d", err);
            return;
        }

        if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
            xpc_release(message);
            return;
        }

        xpc_object_t reply = xpc_dictionary_create_reply(message);

        JBD_MESSAGE_ID msgId = xpc_dictionary_get_uint64(message, "id");

        audit_token_t auditToken = {0};
        xpc_dictionary_get_audit_token(message, &auditToken);
        uid_t clientUid = audit_token_to_euid(auditToken);
        pid_t clientPid = audit_token_to_pid(auditToken);

        switch (msgId) {
            case JBD_MSG_TEST_CALL: {
                int64_t result = 0;
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPINLOCK_FIX_ONLY: {
                pid_t pid = (pid_t)xpc_dictionary_get_int64(message, "pid");
                int64_t result = -1;
                JBLogDebug("jailbreakd: spinlock fix only pid=%d client=%d", pid, clientPid);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_PATCH_CHILD: {
                int64_t result = -1;
                pid_t pid = (pid_t)xpc_dictionary_get_int64(message, "pid");
                bool resume = xpc_dictionary_get_bool(message, "resume");
                pid_t ppid = proc_get_ppid(pid);
                if (ppid == clientPid || ppid == 1) {
                    if (roothide_patch_proc(pid) == 0) {
                        if (resume) {
                            kill(pid, SIGCONT);
                        }
                        result = 0;
                    } else {
                        JBLogError("jailbreakd: spawn patch failed pid=%d", pid);
                    }
                } else {
                    JBLogError("jailbreakd: spawn patch denied ppid=%d client=%d pid=%d", ppid, clientPid, pid);
                }
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_EXEC_START: {
                bool resume = xpc_dictionary_get_bool(message, "resume");
                int64_t result = -1;
                if (spawnExecPatchAdd(clientPid, resume) == 0) {
                    result = 0;
                }
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_EXEC_CANCEL: {
                spawnExecPatchRemove(clientPid);
                int64_t result = 0;
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_EXEC_TRACE_START: {
                int64_t result = -1;
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_EXEC_TRACE_CANCEL: {
                int64_t result = 0;
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            default: {
                JBLogError("jailbreakd: unknown msg id=%llu from client=%d", (uint64_t)msgId, clientPid);
                int64_t result = -1;
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }
        }

        jailbreakd_reply_message(reply);
        xpc_release(message);
    }
}
