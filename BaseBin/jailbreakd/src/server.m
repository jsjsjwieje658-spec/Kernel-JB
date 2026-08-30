//
//  server.m
//  jailbreakd server - handles XPC messages from launchdhook
//
//  Handles process trust patching requests:
//    - JBD_MSG_SPAWN_PATCH_CHILD: patch trust for child processes
//    - JBD_MSG_SPAWN_EXEC_START/CANCEL: handle exec() re-trust
//    - JBD_MSG_EXEC_TRACE_START/CANCEL: ptrace-based monitoring
//    - JBD_MSG_SPINLOCK_FIX_ONLY: spinlock fix
//    - JBD_MSG_TEST_CALL: liveness check
//

#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>
#include <spawn.h>
#include <xpc/xpc.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/log.h>
#include <libjailbreak/roothider.h>

#include "../../libjailbreak/src/roothider/exec_patch.h"
#include "../../libjailbreak/src/roothider/jailbreakd.h"

void jailbreakd_reply_message(xpc_object_t reply) {
    int err = xpc_pipe_routine_reply(reply);
    if (err != 0) {
        JBLogError("jailbreakd: xpc_pipe_routine_reply error %d", err);
    }
}

void jailbreakd_received_message(mach_port_t port) {
    @autoreleasepool {
        xpc_object_t message = NULL;
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
                int64_t result = jbdTestCall(0);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPINLOCK_FIX_ONLY: {
                pid_t pid = (pid_t)xpc_dictionary_get_int64(message, "pid");
                bool resume = xpc_dictionary_get_bool(message, "resume");
                int64_t result = jbdSpinlockFixOnly(pid, resume);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_PATCH_CHILD: {
                pid_t pid = (pid_t)xpc_dictionary_get_int64(message, "pid");
                bool resume = xpc_dictionary_get_bool(message, "resume");
                pid_t ppid = proc_get_ppid(pid);
                int64_t result = -1;
                if (ppid == clientPid || ppid == 1) {
                    result = jbdSpawnPatchChild(pid, resume);
                } else {
                    JBLogError("jailbreakd: spawn patch denied ppid=%d client=%d pid=%d", ppid, clientPid, pid);
                }
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_EXEC_START: {
                const char *execfile = xpc_dictionary_get_string(message, "execfile");
                bool resume = xpc_dictionary_get_bool(message, "resume");
                int64_t result = jbdSpawnExecStart(execfile, resume);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_EXEC_CANCEL: {
                const char *execfile = xpc_dictionary_get_string(message, "execfile");
                int64_t result = jbdSpawnExecCancel(execfile);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_EXEC_TRACE_START: {
                const char *execfile = xpc_dictionary_get_string(message, "execfile");
                bool traced = false;
                int64_t result = jbdExecTraceStart(execfile, &traced);
                xpc_dictionary_set_bool(reply, "traced", traced);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_EXEC_TRACE_CANCEL: {
                const char *execfile = xpc_dictionary_get_string(message, "execfile");
                bool detached = false;
                int64_t result = jbdExecTraceCancel(execfile, &detached);
                xpc_dictionary_set_bool(reply, "detached", detached);
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
        xpc_release(reply);
    }
}
