#include "util.h"
#include <wchar.h>

/* ---------------- buffers ---------------- */
void buf_init(buf_t *b) { b->data = NULL; b->len = 0; b->cap = 0; }
void buf_free(buf_t *b) { if (b->data) free(b->data); b->data = NULL; b->len = b->cap = 0; }
void buf_reset(buf_t *b) { b->len = 0; }

int buf_reserve(buf_t *b, size_t need)
{
    size_t nc;
    u8 *p;
    if (need <= b->cap) return 0;
    nc = b->cap ? b->cap : 256;
    while (nc < need) {
        if (nc > (size_t)-1 / 2) return -1;
        nc *= 2;
    }
    p = (u8 *)realloc(b->data, nc);
    if (!p) return -1;
    b->data = p;
    b->cap = nc;
    return 0;
}

int buf_append(buf_t *b, const void *p, size_t n)
{
    if (!n) return 0;
    if (buf_reserve(b, b->len + n) != 0) return -1;
    memcpy(b->data + b->len, p, n);
    b->len += n;
    return 0;
}

int buf_append_str(buf_t *b, const char *s) { return s ? buf_append(b, s, strlen(s)) : 0; }

int buf_append_printf(buf_t *b, const char *fmt, ...)
{
    va_list ap, ap2;
    int n;
    char *tmp;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return -1; }
    tmp = (char *)malloc((size_t)n + 1);
    if (!tmp) { va_end(ap2); return -1; }
    vsnprintf(tmp, (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    if (buf_append(b, tmp, (size_t)n) != 0) { free(tmp); return -1; }
    free(tmp);
    return 0;
}

int buf_set(buf_t *b, const void *p, size_t n)
{
    b->len = 0;
    return buf_append(b, p, n);
}

void buf_consume(buf_t *b, size_t n)
{
    if (n >= b->len) { b->len = 0; return; }
    memmove(b->data, b->data + n, b->len - n);
    b->len -= n;
}

/* ---------------- memory ---------------- */
void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "oom\n"); exit(2); }
    return p;
}
void *xcalloc(size_t n, size_t s)
{
    void *p = calloc(n ? n : 1, s ? s : 1);
    if (!p) { fprintf(stderr, "oom\n"); exit(2); }
    return p;
}
void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "oom\n"); exit(2); }
    return q;
}
char *xstrdup(const char *s)
{
    size_t n;
    char *p;
    if (!s) return NULL;
    n = strlen(s);
    p = (char *)xmalloc(n + 1);
    memcpy(p, s, n + 1);
    return p;
}
char *xstrndup(const char *s, size_t n)
{
    char *p;
    size_t i;
    if (!s) return NULL;
    for (i = 0; i < n && s[i]; i++);
    p = (char *)xmalloc(i + 1);
    memcpy(p, s, i);
    p[i] = 0;
    return p;
}

/* ---------------- time ---------------- */
u64 now_ms(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    if (!freq.QuadPart) return GetTickCount64();
    return (u64)((c.QuadPart * 1000ULL) / (u64)freq.QuadPart);
}

void sleep_ms(unsigned ms) { Sleep(ms); }

/* ---------------- encodings ---------------- */
static const char HEXD[] = "0123456789abcdef";
char *hex_enc(const u8 *in, size_t n)
{
    char *o = (char *)xmalloc(n * 2 + 1);
    size_t i;
    for (i = 0; i < n; i++) {
        o[i * 2] = HEXD[in[i] >> 4];
        o[i * 2 + 1] = HEXD[in[i] & 15];
    }
    o[n * 2] = 0;
    return o;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_dec(const char *in, u8 **out, size_t *outlen)
{
    size_t n, i;
    u8 *p;
    if (!in) return -1;
    n = strlen(in);
    if (n % 2) return -1;
    p = (u8 *)xmalloc(n / 2 + 1);
    for (i = 0; i < n; i += 2) {
        int a = hexval((unsigned char)in[i]);
        int b = hexval((unsigned char)in[i + 1]);
        if (a < 0 || b < 0) { free(p); return -1; }
        p[i / 2] = (u8)((a << 4) | b);
    }
    *out = p;
    *outlen = n / 2;
    return 0;
}

static const char B64D[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *b64_enc(const u8 *in, size_t n)
{
    size_t olen = ((n + 2) / 3) * 4;
    char *o = (char *)xmalloc(olen + 1);
    size_t i, j = 0;
    for (i = 0; i + 2 < n; i += 3) {
        u32 v = ((u32)in[i] << 16) | ((u32)in[i + 1] << 8) | in[i + 2];
        o[j++] = B64D[(v >> 18) & 63];
        o[j++] = B64D[(v >> 12) & 63];
        o[j++] = B64D[(v >> 6) & 63];
        o[j++] = B64D[v & 63];
    }
    if (i < n) {
        u32 v = (u32)in[i] << 16;
        int rem = (int)(n - i);
        if (rem == 2) v |= (u32)in[i + 1] << 8;
        o[j++] = B64D[(v >> 18) & 63];
        o[j++] = B64D[(v >> 12) & 63];
        o[j++] = rem == 2 ? B64D[(v >> 6) & 63] : '=';
        o[j++] = '=';
    }
    o[j] = 0;
    return o;
}

static int b64val(int c)
{
    const char *p;
    if (c == '=') return -2;
    p = strchr(B64D, c);
    return p ? (int)(p - B64D) : -1;
}

int b64_dec(const char *in, u8 **out, size_t *outlen)
{
    size_t n, i, j = 0, pad = 0;
    u8 *p;
    if (!in) return -1;
    n = strlen(in);
    while (n && (in[n - 1] == '\r' || in[n - 1] == '\n' || in[n - 1] == ' ')) n--;
    while (n && in[n - 1] == '=') { pad++; n--; }
    p = (u8 *)xmalloc((n / 4 + 1) * 3 + 1);
    for (i = 0; i + 3 < n; i += 4) {
        int a = b64val((unsigned char)in[i]), b = b64val((unsigned char)in[i + 1]);
        int c = b64val((unsigned char)in[i + 2]), d = b64val((unsigned char)in[i + 3]);
        u32 v;
        if (a < 0 || b < 0 || c < 0 || d < 0) { free(p); return -1; }
        v = ((u32)a << 18) | ((u32)b << 12) | ((u32)c << 6) | (u32)d;
        p[j++] = (u8)(v >> 16);
        p[j++] = (u8)(v >> 8);
        p[j++] = (u8)v;
    }
    if (i < n) {
        int a = b64val((unsigned char)in[i]), b = (i + 1 < n) ? b64val((unsigned char)in[i + 1]) : 0;
        u32 v;
        if (a < 0 || b < 0) { free(p); return -1; }
        v = ((u32)a << 18) | ((u32)b << 12);
        p[j++] = (u8)(v >> 16);
        if (i + 2 < n) {              /* 3-char tail => 2 output bytes */
            int c3 = b64val((unsigned char)in[i + 2]);
            if (a < 0 || b < 0 || c3 < 0) { free(p); return -1; }
            v |= ((u32)c3 << 6);
            p[j++] = (u8)(v >> 8);
        }
    }
    /* NOTE: 'pad' bytes were already trimmed from n above, so the loop/tail
     * below emits exactly the decoded length.  Subtracting pad again (as the
     * original #4834 code did) truncates 1-2 bytes from every padded input. */
    (void)pad;
    *out = p;
    *outlen = j;
    return 0;
}

/* ---------------- files ---------------- */
int read_file(const char *path, buf_t *out)
{
    HANDLE h;
    DWORD rd;
    u8 tmp[8192];
    wchar_t *wp = widen(path);
    if (!wp) return -1;
    h = CreateFileW(wp, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wp);
    if (h == INVALID_HANDLE_VALUE) return -1;
    while (ReadFile(h, tmp, sizeof(tmp), &rd, NULL) && rd > 0) {
        if (out->len > 256u * 1024u * 1024u) { CloseHandle(h); return -1; }
        if (buf_append(out, tmp, rd) != 0) { CloseHandle(h); return -1; }
    }
    CloseHandle(h);
    return 0;
}

int write_file(const char *path, const void *data, size_t len, int append)
{
    HANDLE h;
    DWORD wr;
    const u8 *p = (const u8 *)data;
    size_t left = len;
    wchar_t *wp = widen(path);
    if (!wp) return -1;
    h = CreateFileW(wp, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                    append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wp);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (append) SetFilePointer(h, 0, NULL, FILE_END);
    while (left) {
        DWORD chunk = (DWORD)(left > 1024u * 1024u ? 1024u * 1024u : left);
        if (!WriteFile(h, p, chunk, &wr, NULL) || wr == 0) { CloseHandle(h); return -1; }
        p += wr;
        left -= wr;
    }
    CloseHandle(h);
    return 0;
}

int path_exists(const char *path)
{
    wchar_t *wp = widen(path);
    DWORD a;
    if (!wp) return 0;
    a = GetFileAttributesW(wp);
    free(wp);
    return a != INVALID_FILE_ATTRIBUTES;
}

char *exe_path(void)
{
    wchar_t wbuf[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(NULL, wbuf, (DWORD)(sizeof(wbuf) / sizeof(wbuf[0])));
    if (!n) return xstrdup("");
    wbuf[(sizeof(wbuf) / sizeof(wbuf[0])) - 1] = 0;
    return narrow(wbuf);
}

char *exe_dir(void)
{
    char *p = exe_path();
    char *s;
    if (!p) return xstrdup(".");
    s = strrchr(p, '\\');
    if (!s) s = strrchr(p, '/');
    if (s) *s = 0; else { free(p); return xstrdup("."); }
    return p;
}

char *path_join(const char *dir, const char *name)
{
    size_t a = strlen(dir ? dir : ""), b = strlen(name ? name : "");
    char *o = (char *)xmalloc(a + b + 2);
    memcpy(o, dir ? dir : "", a);
    if (a && o[a - 1] != '\\' && o[a - 1] != '/') o[a++] = '\\';
    memcpy(o + a, name ? name : "", b + 1);
    return o;
}

int mkdir_p(const char *path)
{
    char *tmp = xstrdup(path);
    char *p;
    for (p = tmp + 1; *p; p++) {
        if (*p == '\\' || *p == '/') {
            wchar_t *wp;
            char saved = *p;
            *p = 0;
            wp = widen(tmp);
            if (wp) { CreateDirectoryW(wp, NULL); free(wp); }
            *p = saved;
        }
    }
    {
        wchar_t *wp = widen(tmp);
        int ok = 0;
        if (wp) {
            if (CreateDirectoryW(wp, NULL)) ok = 1;
            else if (GetLastError() == ERROR_ALREADY_EXISTS) ok = 1;
            free(wp);
        }
        free(tmp);
        return ok ? 0 : -1;
    }
}

/* ---------------- unicode ---------------- */
wchar_t *widen(const char *s)
{
    int n;
    wchar_t *w;
    if (!s) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) {
        n = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
        if (n <= 0) return NULL;
        w = (wchar_t *)xmalloc((size_t)n * sizeof(wchar_t));
        MultiByteToWideChar(CP_ACP, 0, s, -1, w, n);
        return w;
    }
    w = (wchar_t *)xmalloc((size_t)n * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

char *narrow(const wchar_t *w)
{
    int n;
    char *s;
    if (!w) return NULL;
    n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return xstrdup("");
    s = (char *)xmalloc((size_t)n);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

/* ---------------- process execution ---------------- */
static int drain_pipe(HANDLE rd, buf_t *out, int timeout_ms, HANDLE proc, DWORD *exit_code)
{
    u64 start = now_ms();
    char tmp[4096];
    int timed_out = 0;
    *exit_code = 0xFFFFFFFFu;
    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
            DWORD got = 0;
            DWORD want = avail > sizeof(tmp) ? (DWORD)sizeof(tmp) : avail;
            if (ReadFile(rd, tmp, want, &got, NULL) && got > 0) {
                if (out->len < 16u * 1024u * 1024u) buf_append(out, tmp, got);
                continue;
            }
            break;
        }
        {
            DWORD w = WaitForSingleObject(proc, 25);
            if (w == WAIT_OBJECT_0) {
                while (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail > 0) {
                    DWORD got = 0;
                    DWORD want = avail > sizeof(tmp) ? (DWORD)sizeof(tmp) : avail;
                    if (!ReadFile(rd, tmp, want, &got, NULL) || got == 0) break;
                    if (out->len < 16u * 1024u * 1024u) buf_append(out, tmp, got);
                }
                break;
            }
            if (w == WAIT_FAILED) break;
        }
        if (timeout_ms > 0 && (i64)(now_ms() - start) > timeout_ms) { timed_out = 1; break; }
    }
    if (timed_out) {
        TerminateProcess(proc, 0xDEAD);
        WaitForSingleObject(proc, 2000);
    }
    GetExitCodeProcess(proc, exit_code);
    return timed_out ? 1 : 0;
}

int run_proc(const wchar_t *cmdline, buf_t *out, int timeout_ms, int *exit_code)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t *mutable_cmd;
    size_t clen;
    DWORD ec = 0;
    int rc;

    if (!cmdline) return -1;
    clen = wcslen(cmdline);
    mutable_cmd = (wchar_t *)xmalloc((clen + 1) * sizeof(wchar_t));
    wmemcpy(mutable_cmd, cmdline, clen + 1);

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { free(mutable_cmd); return -1; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = NULL;

    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(NULL, mutable_cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        DWORD e = GetLastError();
        CloseHandle(rd); CloseHandle(wr); free(mutable_cmd);
        LOGF("CreateProcessW failed err=%lu cmd=%ls", (unsigned long)e, cmdline);
        return -1;
    }
    CloseHandle(wr);
    CloseHandle(pi.hThread);
    rc = drain_pipe(rd, out, timeout_ms, pi.hProcess, &ec);
    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    free(mutable_cmd);
    if (exit_code) *exit_code = (int)ec;
    return rc;
}

int run_cmd(const char *cmdline, buf_t *out, int timeout_ms, int *exit_code)
{
    wchar_t *wcmd = widen(cmdline);
    wchar_t *full;
    size_t n;
    int rc;
    if (!wcmd) return -1;
    n = wcslen(wcmd);
    full = (wchar_t *)xmalloc((n + 32) * sizeof(wchar_t));
    wcscpy(full, L"cmd.exe /c ");
    wcscat(full, wcmd);
    free(wcmd);
    rc = run_proc(full, out, timeout_ms, exit_code);
    free(full);
    return rc;
}

/* ---------------- logging ---------------- */
static HANDLE g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_log_cs;
static int g_log_cs_init = 0;
static int g_log_debug = 0;

void log_init(const char *path, int debug)
{
    wchar_t *wp;
    g_log_debug = debug;
    if (!g_log_cs_init) { InitializeCriticalSection(&g_log_cs); g_log_cs_init = 1; }
    if (!path) return;
    wp = widen(path);
    if (!wp) return;
    g_log = CreateFileW(wp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL, NULL);
    free(wp);
    if (g_log == INVALID_HANDLE_VALUE) g_log = INVALID_HANDLE_VALUE;
}

void log_close(void)
{
    if (g_log != INVALID_HANDLE_VALUE) { CloseHandle(g_log); g_log = INVALID_HANDLE_VALUE; }
}

void LOGF(const char *fmt, ...)
{
    char line[2048];
    int n;
    va_list ap;
    SYSTEMTIME st;
    DWORD wr;
    if (g_log == INVALID_HANDLE_VALUE && !g_log_debug) return;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof(line) - 1) n = (int)sizeof(line) - 1;
    if (g_log != INVALID_HANDLE_VALUE) {
        char out[2200];
        int m;
        GetLocalTime(&st);
        m = snprintf(out, sizeof(out), "%04d-%02d-%02d %02d:%02d:%02d [%lu] %s\r\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                     (unsigned long)GetCurrentProcessId(), line);
        if (m > 0) {
            EnterCriticalSection(&g_log_cs);
            WriteFile(g_log, out, (DWORD)m, &wr, NULL);
            LeaveCriticalSection(&g_log_cs);
        }
    }
}

/* ---------------- random ---------------- */
typedef BOOLEAN(WINAPI *rtlgen_fn)(PVOID, ULONG);

void rand_bytes(void *out, size_t n)
{
    static rtlgen_fn fn = NULL;
    static int tried = 0;
    u8 *p = (u8 *)out;
    if (!tried) {
        HMODULE h = LoadLibraryA("advapi32.dll");
        if (h) fn = (rtlgen_fn)GetProcAddress(h, "SystemFunction036");
        tried = 1;
    }
    if (fn) {
        size_t off = 0;
        while (off < n) {
            ULONG chunk = (ULONG)((n - off) > 0x40000000u ? 0x40000000u : (n - off));
            if (!fn(p + off, chunk)) break;
            off += chunk;
        }
        if (off == n) return;
    }
    {
        LARGE_INTEGER q;
        QueryPerformanceCounter(&q);
        for (size_t i = 0; i < n; i++) {
            p[i] = (u8)((q.QuadPart >> ((i % 8) * 8)) ^ (GetTickCount() >> (i % 16)) ^ (i * 131));
            q.QuadPart = q.QuadPart * 6364136223846793005ULL + 1442695040888963407ULL;
        }
    }
}

void rand_hex(char *out, size_t nbytes)
{
    u8 *b = (u8 *)xmalloc(nbytes);
    rand_bytes(b, nbytes);
    for (size_t i = 0; i < nbytes; i++) {
        out[i * 2] = HEXD[b[i] >> 4];
        out[i * 2 + 1] = HEXD[b[i] & 15];
    }
    out[nbytes * 2] = 0;
    free(b);
}

int ci_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    return _stricmp(a, b) == 0;
}

char *env_dup(const char *name)
{
    DWORD n;
    wchar_t *wn = widen(name);
    if (!wn) return NULL;
    n = GetEnvironmentVariableW(wn, NULL, 0);
    free(wn);
    if (!n) return NULL;
    {
        wchar_t *wv = (wchar_t *)xmalloc((size_t)n * sizeof(wchar_t));
        wchar_t *wn2 = widen(name);
        char *res;
        if (wn2) {
            GetEnvironmentVariableW(wn2, wv, n);
            free(wn2);
        } else {
            wv[0] = 0;
        }
        res = narrow(wv);
        free(wv);
        return res;
    }
}
