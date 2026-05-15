#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <android/log.h>
#include <sys/stat.h>
#include <time.h>

#define LOG_TAG  "libscriptspy"
#define LOGFILE  "/storage/emulated/0/scriptspy_log.txt"
#define DUMPDIR  "/storage/emulated/0/ScriptSpy"
#define EXPORT   __attribute__((visibility("default")))

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
typedef int (*luaL_loadbuffer_t)(lua_State*, const char*, size_t, const char*);
static luaL_loadbuffer_t orig_loadbuffer = nullptr;

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

static int hook_loadbuffer(lua_State* L, const char* buff, size_t sz, const char* name)
{
    logff_("[ScriptSpy] HOOK DIPANGGIL name=%s sz=%zu", name ? name : "(null)", sz);

    if (g_enabled && buff && sz > 0) {
        g_dump_count++;

        int is_bytecode = (sz >= 3 &&
                           (unsigned char)buff[0] == 0x1b &&
                           buff[1] == 'L' && buff[2] == 'J');

        const char* raw_name = name ? name : "chunk";
        if (raw_name[0] == '@') raw_name++;

        char safe_name[128];
        sanitize_name(raw_name, safe_name, sizeof(safe_name));

        char ts[32];
        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);
        snprintf(ts, sizeof(ts), "%ld", tp.tv_sec % 100000);

        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s/%s_%s%s",
                 DUMPDIR, safe_name, ts,
                 is_bytecode ? ".luajit" : ".lua");

        FILE* f = fopen(outpath, "wb");
        if (f) {
            fwrite(buff, 1, sz, f);
            fclose(f);
            logff_("[ScriptSpy] #%d OK: %s (%zu bytes)", g_dump_count, outpath, sz);
        } else {
            logff_("[ScriptSpy] #%d GAGAL fopen: %s", g_dump_count, outpath);
        }
    }
    return orig_loadbuffer(L, buff, sz, name);
}

static void _spy_enable(void)  { g_enabled = 1; }
static void _spy_disable(void) { g_enabled = 0; }
static int  _spy_is_on(void)   { return g_enabled; }
static int  _spy_count(void)   { return g_dump_count; }

struct ScriptSpyAPI {
    void (*enable)(void); void (*disable)(void);
    int  (*is_on)(void);  int  (*count)(void);
};

extern "C" {

EXPORT ScriptSpyAPI scriptspy_api = {
    _spy_enable, _spy_disable, _spy_is_on, _spy_count,
};

EXPORT void* __GetModInfo() {
    static const char* info =
        "scriptspy|1.2|Lua Script Dumper|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    logf_("[ScriptSpy] OnModPreLoad v1.2");
    mkdir(DUMPDIR, 0777);
}

EXPORT void OnModLoad() {
    logf_("[ScriptSpy] OnModLoad mulai");

    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { logf_("[ScriptSpy] ERROR: libdobby"); return; }

    auto dobbyHook = (int(*)(void*,void*,void**))
                        dlsym(hDobby, "DobbyHook");
    if (!dobbyHook) { logf_("[ScriptSpy] ERROR: DobbyHook sym"); return; }

    // Buka libluajit secara spesifik — RTLD_NOLOAD jika sudah ada di memori
    // RTLD_NOLOAD = tidak load ulang, ambil handle yang sudah ada
    void* hLua = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hLua) {
        logf_("[ScriptSpy] RTLD_NOLOAD gagal, coba load normal");
        hLua = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_LOCAL);
    }
    if (!hLua) { logf_("[ScriptSpy] ERROR: libluajit tidak bisa dibuka"); return; }
    logff_("[ScriptSpy] hLua handle = %p", hLua);

    // Ambil alamat dari handle spesifik libluajit — bukan PLT stub
    void* target = dlsym(hLua, "luaL_loadbuffer");
    if (!target) { logf_("[ScriptSpy] ERROR: simbol tidak ditemukan"); return; }
    logff_("[ScriptSpy] target addr = %p", target);

    // Cek apakah ini Thumb: bit 0 harus 0 dari dlsym, tapi coba +1 jika gagal
    int ret = dobbyHook(target, (void*)hook_loadbuffer, (void**)&orig_loadbuffer);
    logff_("[ScriptSpy] DobbyHook ret=%d orig=%p", ret, orig_loadbuffer);

    if (ret != 0 || !orig_loadbuffer) {
        // Coba dengan Thumb bit +1
        logf_("[ScriptSpy] Coba Thumb bit...");
        void* target_thumb = (void*)((uintptr_t)target | 1);
        orig_loadbuffer = nullptr;
        ret = dobbyHook(target_thumb, (void*)hook_loadbuffer, (void**)&orig_loadbuffer);
        logff_("[ScriptSpy] Thumb retry ret=%d orig=%p", ret, orig_loadbuffer);
        if (ret != 0 || !orig_loadbuffer) {
            logf_("[ScriptSpy] ERROR: DobbyHook gagal total");
            return;
        }
    }

    logf_("[ScriptSpy] Hook terpasang! Monitoring aktif.");
}

} // extern "C"
