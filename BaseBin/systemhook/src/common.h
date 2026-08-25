// RootHide port: wrapper that redirects to Kernel-JB's existing common/common.h
// (Kernel-JB has common/ subdir; Relaxin's roothider_*.{c,m} expect common.h at parent level).
#ifndef KJ_SYSTEMHOOK_COMMON_WRAPPER_H
#define KJ_SYSTEMHOOK_COMMON_WRAPPER_H
#include "common/common.h"
#endif
