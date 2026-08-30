#ifndef JB_LOG_H
#define JB_LOG_H

#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
void JBLogDebugFunction(const char *format, ...) __attribute__((format(printf, 1, 2)));
void JBLogErrorFunction(const char *format, ...) __attribute__((format(printf, 1, 2)));

#define JBLogDebug(...) do { \
    JBLogDebugFunction(__VA_ARGS__); \
} while (0)

#define JBLogError(...) do { \
    JBLogErrorFunction(__VA_ARGS__); \
} while (0)
#else
// Production builds: BOTH macros compile to nothing.
// This strips ALL format strings ("roothide", "jailbreak", "systemhook",
// "basebin", "com.opa334" etc.) from the binary's __cstring section,
// defeating `strings binary | grep` detection by banking apps.
// Matches Dopamine2-roothide's log.h behaviour.
#define JBLogDebug(...) do { } while (0)
#define JBLogError(...) do { } while (0)
#endif

#endif
