//
//  server.m
//  jailbreakd server - handles XPC messages from launchdhook
//
//  IMPORTANT: This is the SERVER side. Do NOT call jbd* client functions
//  (jbdTestCall, jbdSpawnPatchChild, etc.) — those SEND XPC messages TO
//  jailbreakd and would create an infinite loop. Call the actual
//  implementations directly: roothide_patch_proc(), spawnExecPatchAdd(), etc.
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

// Server-side implementations (NOT client wrappers)
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
            ((void (*)(xpc_object_t))xpc_release)(message);
            return;
        }

        xpc_object_t reply = xpc_dictionary_create_reply(message);
        if (!reply) {
            JBLogError("jailbreakd: xpc_dictionary_create_reply returned NULL");
            ((void (*)(xpc_object_t))xpc_release)(message);
            return;
        }

        JBD_MESSAGE_ID msgId = xpc_dictionary_get_uint64(message, "id");

        audit_token_t auditToken = {0};
        xpc_dictionary_get_audit_token(message, &auditToken);
        uid_t clientUid = audit_token_to_euid(auditToken);
        pid_t clientPid = audit_token_to_pid(auditToken);

        switch (msgId) {
            case JBD_MSG_TEST_CALL: {
                int64_t value = xpc_dictionary_get_int64(message, "value");
                xpc_dictionary_set_int64(reply, "result", value * 2);
                if (clientUid == 0) abort(); // crashreporter test
                break;
            }

            case JBD_MSG_SPINLOCK_FIX_ONLY: {
                // Not supported in stock-dyld policy
                pid_t pid = (pid_t)xpc_dictionary_get_int64(message, "pid");
                JBLogError("jailbreakd: spinlock fix rejected pid=%d client=%d", pid, clientPid);
                xpc_dictionary_set_int64(reply, "result", ENOTSUP);
                break;
            }

            case JBD_MSG_SPAWN_PATCH_CHILD: {
                pid_t pid = (pid_t)xpc_dictionary_get_int64(message, "pid");
                bool resume = xpc_dictionary_get_bool(message, "resume");
                pid_t ppid = proc_get_ppid(pid);
                int64_t result = -1;
                if (ppid == clientPid || ppid == 1) {
                    // Call the ACTUAL server-side implementation
                    result = roothide_patch_proc(pid);
                    if (result == 0 && resume) {
                        kill(pid, SIGCONT);
                    }
                } else {
                    JBLogError("jailbreakd: spawn patch denied ppid=%d client=%d pid=%d", ppid, clientPid, pid);
                }
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_EXEC_START: {
                // Client request has no pid field. Authenticated XPC sender
                // is the target, matching upstream RootHide protocol.
                bool resume = xpc_dictionary_get_bool(message, "resume");
                int64_t result = spawnExecPatchAdd(clientPid, resume);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            case JBD_MSG_SPAWN_EXEC_CANCEL:
                spawnExecPatchDel(clientPid);
                xpc_dictionary_set_int64(reply, "result", 0);
                break;

            case JBD_MSG_EXEC_TRACE_START: {
                uint64_t traced = xpc_dictionary_get_uint64(message, "traced");
                ((void (*)(xpc_object_t))xpc_retain)(reply);
                dispatch_async(dispatch_get_global_queue(0, 0), ^{
                    int64_t result = execTraceProcess(clientPid, traced);
                    xpc_dictionary_set_int64(reply, "result", result);
                    jailbreakd_reply_message(reply);
                    ((void (*)(xpc_object_t))xpc_release)(reply);
                });
                ((void (*)(xpc_object_t))xpc_release)(message);
                ((void (*)(xpc_object_t))xpc_release)(reply);
                return;
            }

            case JBD_MSG_EXEC_TRACE_CANCEL: {
                uint64_t detached = xpc_dictionary_get_uint64(message, "detached");
                int64_t result = execTraceCancel(clientPid, detached);
                xpc_dictionary_set_int64(reply, "result", result);
                break;
            }

            default: {
                JBLogError("jailbreakd: unknown msg id=%llu from client=%d", (uint64_t)msgId, clientPid);
                xpc_dictionary_set_int64(reply, "result", -1);
                break;
            }
        }

        jailbreakd_reply_message(reply);
        ((void (*)(xpc_object_t))xpc_release)(message);
        ((void (*)(xpc_object_t))xpc_release)(reply);
    }
}
