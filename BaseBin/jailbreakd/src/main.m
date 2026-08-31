//
//  main.m
//  jailbreakd - Kernel-JB port
//
//  Daemon that handles process trust patching (tree trust model):
//    - JBD_MSG_SPAWN_PATCH_CHILD: patch trust for child processes when spawned
//    - JBD_MSG_SPAWN_EXEC_START/CANCEL: re-patch trust when process execs itself
//    - JBD_MSG_EXEC_TRACE_START/CANCEL: ptrace-based monitoring
//

#include <Foundation/Foundation.h>
#include <kern_memorystatus.h>
#include <libproc.h>
#include <spawn.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/log.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/roothider.h>

void jailbreakd_received_message(mach_port_t port);

void setJetsamLimit(uint32_t sizeInMB, bool is_fatal_limit) {
    uint32_t cmd = is_fatal_limit ? MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT
                                  : MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK;
    int rc = memorystatus_control(cmd, getpid(), sizeInMB, NULL, 0);
    if (rc < 0) {
        JBLogError("jailbreakd: memorystatus_control failed status=%d errno=%d", rc, errno);
        exit(rc);
    }
}

int main(int argc, char* argv[]) {
    setJetsamLimit(50, false);

    JBLogDebug("jailbreakd startup status=begin pid=%d", getpid());

    @autoreleasepool {
        // Get bootstrap port from registered ports (passed by launchd via posix_spawn registered ports)
        mach_port_t *registeredPorts = NULL;
        mach_msg_type_number_t registeredPortsCount = 0;
        kern_return_t kr = mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount);
        if (kr != KERN_SUCCESS || registeredPortsCount < 3) {
            JBLogError("jailbreakd: mach_ports_lookup error: %d, %x, %s", registeredPortsCount, kr, mach_error_string(kr));
            return 1;
        }
        mach_port_t bootstraport = registeredPorts[2];
        if (!MACH_PORT_VALID(bootstraport)) {
            JBLogError("jailbreakd: invalid bootstraport");
            return 2;
        }
        // Clean up registered ports array
        mach_port_t oldPort = registeredPorts[2];
        registeredPorts[2] = MACH_PORT_NULL;
        mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);
        vm_deallocate(mach_task_self(), (vm_address_t)registeredPorts, registeredPortsCount * sizeof(mach_port_t));

        // Set custom bootstrap port for jbclient
        jbclient_xpc_set_custom_port(bootstraport);

        // Initialize jailbreak primitives
        int ret = jbclient_initialize_primitives();
        if (ret != 0) {
            JBLogError("jailbreakd: Failed to initialize primitives: %d", ret);
            return 3;
        }
        JBLogDebug("jailbreakd primitives status=ready");

        // Handle respawn
        if (getenv("RESPAWN_REQUIRED")) {
            unsetenv("RESPAWN_REQUIRED");
            JBLogDebug("jailbreakd: RESPAWN_REQUIRED consumed pid=%d", getpid());
        }

        // Check in with launchdhook to get server port
        mach_port_t serverPort = jbclient_jailbreakd_checkin();
        if (!MACH_PORT_VALID(serverPort)) {
            JBLogError("jailbreakd: Failed to check in server port");
            return 6;
        }

        JBLogDebug("jailbreakd server status=ready port=%x", serverPort);

        // Start XPC message loop
        dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV,
                                                          (uintptr_t)serverPort,
                                                          0,
                                                          dispatch_get_main_queue());
        dispatch_source_set_event_handler(source, ^{
            jailbreakd_received_message(serverPort);
        });
        dispatch_resume(source);

        dispatch_main();
    }

    return 0;
}
