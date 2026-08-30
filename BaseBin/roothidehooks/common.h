
#include <stdbool.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/codesign.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define RHLogDebug(...) NSLog(__VA_ARGS__)
#define RHLogError(...) NSLog(__VA_ARGS__)
#else
// Production: strip ALL log strings (roothide, jailbreak, systemhook etc.)
#define RHLogDebug(...) do { } while (0)
#define RHLogError(...) do { } while (0)
#endif

bool isJailbreakBundlePath(const char *path);
