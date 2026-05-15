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
typedef const char* (*lua_Reader)(lua_State*, void*, size_t*);
typedef int (*lua_load_t)(lua_State*, lua_Reader, void*, const char*);

static lua_load_t orig_lua_load = nullptr;

static int  g_enabled    = 1;
static int  g_dump_count = 0;

// Buffer akumulasi untuk tangkap semua chunk dari reader
#define ACCUM_MAX (512 * 1024)  // 512KB max per script
static char  g_accum[ACCUM_MAX];
static size_t g_accum_sz = 0;

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
    if (!buff || sz == 0) return;
    g_dump_count++;
    int is_bc = (sz >= 3 && (unsigned char)buff[0] == 0x1b &&
                 buff[1] == 'L' && buff[2] == 'J');
    const char* raw = name ? name : "chunk";
    if (raw[0] == '@') raw++;
    char safe[128]; sanitize_name(raw, safe, sizeof(safe));
    char ts[32]; struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    snprintf(ts, sizeof(ts), "%ld", tp.tv_sec % 100000);
    char out[512];
    snprintf(out, sizeof(out), "%s/%s_%s%s",
             DUMPDIR, safe, ts, is_bc ? ".luajit" : ".lua");
    FILE* f = fopen(out, "wb");
    if (f) {
        fwrite(buff, 1, sz, f); fclose(f);
        logff_("[ScriptSpy] #%d %s (%zu b, %s)",
               g_dump_count, out, sz, is_bc ? "bytecode" : "plaintext");
    } else {
        logff_("[ScriptSpy] #%d GAGAL fopen: %s errno=%d", g_dump_count, out, errno);
    }
}

// Wrapper reader — akumulasi semua chunk lalu forward ke reader asli
struct ReaderCtx {
    lua_Reader  orig_reader;
    void*       orig_data;
    const char* chunkname;
};

static const char* spy_reader(lua_State* L, void* data, size_t* size) {
    ReaderCtx* ctx = (ReaderCtx*)data;
    const char* chunk = ctx->orig_reader(L, ctx->orig_data, size);
    if (chunk && *size > 0 && g_enabled) {
        size_t avail = ACCUM_MAX - g_accum_sz;
        size_t copy  = (*size < avail) ? *size : avail;
        memcpy(g_accum + g_accum_sz, chunk, copy);
        g_accum_sz += copy;
    }
    return chunk;
}

static int hook_lua_load(lua_State* L, lua_Reader reader,
                          void* data, const char* chunkname)
{
    logff_("[ScriptSpy] lua_load name=%s", chunkname ? chunkname : "(null)");

    if (!g_enabled) return orig_lua_load(L, reader, data, chunkname);

    // Reset akumulator
    g_accum_sz = 0;

    // Wrap reader dengan spy_reader
    ReaderCtx ctx;
    ctx.orig_reader = reader;
    ctx.orig_data   = data;
    ctx.chunkname   = chunkname;

    int ret = orig_lua_load(L, spy_reader, &ctx, chunkname);

    // Dump hasil akumulasi
    if (g_accum_sz > 0) {
        do_dump(g_accum, g_accum_sz, chunkname);
    } else {
        logff_("[ScriptSpy] lua_load: akumulator kosong (reader tidak dipanggil?)");
    }

    return ret;
}

static void _spy_enable(void)  { g_enabled = 1; logf_("[ScriptSpy] on");  }
static void _spy_disable(void) { g_enabled = 0; logf_("[ScriptSpy] off"); }
static int  _spy_is_on(void)   { return g_enabled; }
static int  _spy_count(void)   { return g_dump_count; }
struct ScriptSpyAPI {
    void(*enable)(void); void(*disable)(void);
    int (*is_on)(void);  int (*count)(void);
};

extern "C" {

EXPORT ScriptSpyAPI scriptspy_api = {
    _spy_enable, _spy_disable, _spy_is_on, _spy_count,
};

EXPORT void* __GetModInfo() {
    static const char* info = "scriptspy|1.4|Lua Script Dumper via lua_load hook|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    remove(LOGFILE);
    logf_("[ScriptSpy] OnModPreLoad v1.4");
    mkdir(DUMPDIR, 0777);
}

EXPORT void OnModLoad() {
    logf_("[ScriptSpy] OnModLoad mulai");

    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) { logf_("[ScriptSpy] ERROR: libdobby"); return; }
    auto dobbyHook = (int(*)(void*,void*,void**))dlsym(hDobby, "DobbyHook");
    if (!dobbyHook) { logf_("[ScriptSpy] ERROR: DobbyHook"); return; }

    void* hLua = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_NOLOAD);
    if (!hLua) hLua = dlopen("libluajit-5.1.so", RTLD_NOW | RTLD_LOCAL);
    if (!hLua) { logf_("[ScriptSpy] ERROR: libluajit"); return; }

    void* addr = dlsym(hLua, "lua_load");
    if (!addr) { logf_("[ScriptSpy] ERROR: lua_load tidak ditemukan"); return; }
    logff_("[ScriptSpy] lua_load addr=%p", addr);

    int ret = dobbyHook(addr, (void*)hook_lua_load, (void**)&orig_lua_load);
    logff_("[ScriptSpy] DobbyHook ret=%d orig=%p", ret, orig_lua_load);

    if (ret != 0 || !orig_lua_load) {
        logf_("[ScriptSpy] ERROR: hook gagal");
        return;
    }

    logf_("[ScriptSpy] Hook lua_load terpasang! Monitoring aktif.");
}

} // extern "C"
