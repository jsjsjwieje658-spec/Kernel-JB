#include <libjailbreak/jbserver.h>

extern struct jbserver_domain gSystemwideDomain;
extern struct jbserver_domain gPlatformDomain;
extern struct jbserver_domain gWatchdogDomain;
extern struct jbserver_domain gRootDomain;
extern struct jbserver_domain gDopamineDomain;
extern struct jbserver_domain gRoothideDomain;

// IMPORTANT: the dispatcher in jbserver.c walks `server->domains[]` by index.
// It starts at `domains[0]` and iterates `for (i = 1; i < domainIdx; i++)`,
// picking up `domains[i]` each iteration. The loop ABORTS as soon as it hits
// a NULL entry (because of `&& domain` in the for condition). This means the
// array MUST be densely packed — no gaps allowed — otherwise later domains
// would be unreachable.
//
// Therefore `JBS_DOMAIN_ROOTHIDE` is set to 6 (right after `JBS_DOMAIN_DOPAMINE`
// = 5) so that `domains[5]` (= `&gRoothideDomain`) is reachable when the
// dispatcher walks `i=1..5` for `domainIdx=6`.
struct jbserver_impl gGlobalServer = {
        .maxDomain = 1,
        .domains = (struct jbserver_domain*[]){
                &gSystemwideDomain,  // index 0 -> domain 1 (SYSTEMWIDE)
                &gPlatformDomain,    // index 1 -> domain 2 (PLATFORM)
                &gWatchdogDomain,    // index 2 -> domain 3 (WATCHDOG)
                &gRootDomain,        // index 3 -> domain 4 (ROOT)
                &gDopamineDomain,    // index 4 -> domain 5 (DOPAMINE)
                &gRoothideDomain,    // index 5 -> domain 6 (ROOTHIDE)
                NULL,
        }
};