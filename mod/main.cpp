#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/stat.h>
#include <time.h>

#define LOG_TAG "libscriptspy"
#define LOGFILE "/storage/emulated/0/scriptspy_log.txt"
#define DUMPDIR "/storage/emulated/0/ScriptSpy"
#define EXPORT  __attribute__((visibility("default")))

static void logf_(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s", msg);
}
static void logff_(const char* fmt, ...) {
    char buf[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    logf_(buf);
}

typedef struct lua_State lua_State;
typedef int (*luaL_loadbuffer_t) (lua_State*, const char*, size_t, const char*);
typedef int (*luaL_loadbufferx_t)(lua_State*, const char*, size_t, const char*, const char*);
typedef int (*lua_load_t)        (lua_State*, void*, void*, const char*);

static luaL_loadbuffer_t  orig_loadbuffer  = nullptr;
static luaL_loadbufferx_t orig_loadbufferx = nullptr;

static int g_enabled    = 1;
static int g_dump_count = 0;

static void sanitize_name(const char* src, char* dst, size_t dsz) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dsz; i++) {
        char c = src[i];
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
             c=='_'||c=='-'||c=='.') dst[j++] = c;
        else if (c=='/'||c=='\\') dst[j++] = '_';
    }
    dst[j] = '\0';
    if (j == 0) snprintf(dst, dsz, "unknown_%d", g_dump_count);
}

static void do_dump(const char* buff, size_t sz, const char* name) {
    g_dump_count++;
    int is_bytecode = (sz >= 3 &&
                       (unsigned char)buff[0] == 0x1b &&
                       buff[1] == 'L' && buff[2] == 'J');
    const char* raw = name ? name : "chunk";
    if (raw[0] == '@') raw++;
    char safe[128]; sanitize_name(raw, safe, sizeof(safe));
    char ts[32]; struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    snprintf(ts, sizeof(ts), "%ld", tp.tv_sec % 100000);
    char out[512];
    snprintf(out, sizeof(out), "%s/%s_%s%s",
             DUMPDIR, safe, ts, is_bytecode ? ".luajit" : ".lua");
    FILE* f = fopen(out, "wb");
    if (f) { fwrite(buff, 1, sz, f); fclose(f);
        logff_("[ScriptSpy] #%d OK: %s (%zu b, %s)",
               g_dump_count, out, sz, is_bytecode ? "bc" : "txt");
    } else {
        logff_("[ScriptSpy] #%d GAGAL fopen: %s", g_dump_count, out);
    }
}

static int hook_loadbuffer(lua_State* L, const char* buff, size_t sz, const char* name) {
    logff_("[ScriptSpy] loadbuffer name=%s sz=%zu", name?name:"null", sz);
    if (g_enabled && buff && sz > 0) do_dump(buff, sz, name);
    return orig_loadbuffer(L, buff, sz, name);
}

static int hook_loadbufferx(lua_State* L, const char* buff, size_t sz,
                             const char* name, const char* mode) {
    logff_("[ScriptSpy] loadbufferx name=%s sz=%zu mode=%s",
           name?name:"null", sz, mode?mode:"null");
    if (g_enabled && buff && sz > 0) do_dump(buff, sz, name);
    return orig_loadbufferx(L, buff, sz, name, mode);
}

static void _spy_enable(void)  { g_enabled = 1; }
static void _spy_disable(void) { g_enabled = 0; }
static int  _spy_is_on(void)   { return g_enabled; }
static int  _spy_count(void)   { return g_dump_count; }
struct ScriptSpyAPI {
    void(*enable)(void); void(*disable)(void);
    int (*is_on)(void);  int (*count)(void);
};

static int try_hook(void* dobbyHook_fn, void* hLib,
                    const char* sym, void* hook_fn, void** orig_out) {
    auto dHook = (int(*)(void*,void*,void**))dobbyHook_fn;
    void* addr = dlsym(hLib, sym);
    if (!addr) { logff_("[ScriptSpy] sym tidak ada: %s", sym); return -1; }
    logff_("[ScriptSpy] %s addr=%p", sym, addr);
    int r = dHook(addr, hook_fn, orig_out);
    logff_("[ScriptSpy] hook %s ret=%d orig=%p", sym, r, *orig_out);
    return r;
}

extern "C" {

EXPORT ScriptSpyAPI scriptspy_api = {
    _spy_enable, _spy_disable, _spy_is_on, _spy_count,
};

EXPORT void* __GetModInfo() {
    static const char* info = "scriptspy|1.3|Lua Script Dumper|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    logf_("[ScriptSpy] OnModPreLoad v1.3");
    mkdir(DUMPDIR, 0777);
}

EXPORT void OnModLoad() {
    logf_("[ScriptSpy] OnModLoad mulai");

    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { logf_("[ScriptSpy] ERROR: libdobby"); return; }
    void* dHook = dlsym(hDobby, "DobbyHook");
    if (!dHook)  { logf_("[ScriptSpy] ERROR: DobbyHook sym"); return; }

    void* hLua = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hLua) hLua = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_LOCAL);
    if (!hLua) { logf_("[ScriptSpy] ERROR: libluajit"); return; }
    logff_("[ScriptSpy] hLua=%p", hLua);

    // Hook luaL_loadbuffer
    try_hook(dHook, hLua, "luaL_loadbuffer",
             (void*)hook_loadbuffer, (void**)&orig_loadbuffer);

    // Hook luaL_loadbufferx
    try_hook(dHook, hLua, "luaL_loadbufferx",
             (void*)hook_loadbufferx, (void**)&orig_loadbufferx);

    logf_("[ScriptSpy] selesai — monitoring aktif");
}

} // extern "C"
