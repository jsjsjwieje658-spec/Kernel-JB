#ifndef ROOTHIDER_H
#define ROOTHIDER_H

#include "roothider/common.h"
#include "roothider/ptrace.h"
#include "roothider/mach_exc.h"
#include "roothider/exec_patch.h"
#include "roothider/jailbreakd.h"
#include "roothider/xpc_private.h"
#include "roothider/crashreporter.h"
// RootHide port: include the compat stubs so all roothider/*.m files see the
// declarations for system_info_uses_sptm, jb_trustcache_append_entries,
// trustcache_query_cdhash, csd_superblob_is_adhoc_signed,
// macho_calculate_adhoc_cdhash, etc. (forward-declared in roothide_compat_stubs.h,
// stubbed in roothide_compat_stubs.c).
#include "roothide_compat_stubs.h"

extern int roothide_unsupport_request(void);
extern bool roothide_domain_allowed(audit_token_t clientToken);

#endif // ROOTHIDER_H
