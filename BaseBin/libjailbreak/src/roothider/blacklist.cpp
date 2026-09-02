#include <map>
#include <set>
#include <bsm/audit.h>
#include <pthread.h>
#include <dispatch/dispatch.h>

extern "C" {

#include <libproc.h>
#include <sys/proc_info.h>

#include "../libjailbreak.h"
#include "common.h"

extern int audit_token_to_pidversion(audit_token_t atoken);
}

//do not use cxx auto constructors

static std::set<pid_t *> *uncachedBlacklistedProcesses;
static std::map<pid_t, int> *blacklistedProcessesState;

static void cxx_global_vars_init() {
    uncachedBlacklistedProcesses = new std::set<pid_t *>();
    blacklistedProcessesState = new std::map<pid_t, int>();
}

static pthread_rwlock_t stateLock = {0};

static void stateLockInit() {
    pthread_rwlock_init(&stateLock, NULL);
}
static void stateReadLock() {
    pthread_rwlock_rdlock(&stateLock);
}
static void stateReadUnlock() {
    pthread_rwlock_unlock(&stateLock);
}
static void stateWriteLock() {
    pthread_rwlock_wrlock(&stateLock);
}
static void stateWriteUnlock() {
    pthread_rwlock_unlock(&stateLock);
}

static void initBlacklistState() {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        stateLockInit();
        cxx_global_vars_init();
    });
}

static bool _isBlacklistedProcess(pid_t pid, int pidversion) {
    initBlacklistState();

    bool blacklisted = false;

    stateReadLock();

    // KJB FIX v2: No syscall inside the lock. Copy pid values to local
    // variables while holding the lock to avoid use-after-free if a writer
    // frees the pointer after we release. We do NOT call proc_get_pidversion
    // here — the caller passes pidversion; for the uncached set we treat any
    // matching pid as blacklisted (pid reuse is rare in the millisecond-scale
    // spawn window, and commitBlacklistProcessId will move the pid into the
    // version-keyed cache where reuse is properly handled).
    for (auto it = uncachedBlacklistedProcesses->begin(); it != uncachedBlacklistedProcesses->end(); ++it) {
        pid_t *pidp = *it;
        if (pidp && *pidp > 0 && *pidp == pid) {
            blacklisted = true;
            break;
        }
    }

    if (!blacklisted) {
        auto it = blacklistedProcessesState->find(pid);
        if (it != blacklistedProcessesState->end()) {
            int cached_pidversion = it->second;
            if (cached_pidversion == pidversion) {
                blacklisted = true;
            }
        }
    }

    stateReadUnlock();

    return blacklisted;
}

extern "C" bool isBlacklistedToken(audit_token_t *token) {
    pid_t pid = audit_token_to_pid(*token);
    int pidversion = audit_token_to_pidversion(*token);
    return _isBlacklistedProcess(pid, pidversion);
}

extern "C" bool isBlacklistedPid(pid_t pid) {
    return _isBlacklistedProcess(pid, proc_get_pidversion(pid));
}

extern "C" pid_t *allocBlacklistProcessId() {
    initBlacklistState();

    pid_t *pidp = (pid_t *)malloc(sizeof(pid_t));

    *pidp = 0;

    stateWriteLock();

    uncachedBlacklistedProcesses->insert(pidp);

    stateWriteUnlock();

    return pidp;
}

extern "C" void commitBlacklistProcessId(pid_t *pidp) {
    initBlacklistState();

    pid_t pid = *pidp;

    // KJB FIX v2: Resolve pidversion BEFORE acquiring the write lock so we
    // don't hold a lock across a syscall. The previous implementation
    // could cause priority inversion when many blacklisted apps spawn
    // simultaneously and the lock holder is preempted by a higher-priority
    // thread needing the same lock for a syscall. proc_get_pidversion is
    // also a non-trivial syscall (sysctl traversal of allproc); calling it
    // under the lock could block writers for hundreds of microseconds.
    int pidversion = 0;
    if (pid > 0) {
        pidversion = proc_get_pidversion(pid);
    }

    stateWriteLock();

    if (pid > 0 && pidversion > 0) {
        (*blacklistedProcessesState)[pid] = pidversion;
    }

    uncachedBlacklistedProcesses->erase(pidp);

    free(pidp);

    stateWriteUnlock();
}
