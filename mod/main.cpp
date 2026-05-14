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

// ─── Logging ────────────────────────────────────────────────────────────────

static void logf_(const char* msg) {
    FILE* f = fopen(LOGFILE, "a");
    if (f) { fprintf(f, "%s\n", msg); fclose(f); }
    __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "%s", msg);
}

static void logff_(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    logf_(buf);
}

// ─── Lua types (minimal, cukup untuk hook) ──────────────────────────────────

typedef struct lua_State lua_State;

typedef int (*luaL_loadbuffer_t)(lua_State* L,
                                  const char* buff,
                                  size_t sz,
                                  const char* name);

static luaL_loadbuffer_t orig_loadbuffer = nullptr;

// ─── State ──────────────────────────────────────────────────────────────────

static int  g_enabled    = 1;
static int  g_dump_count = 0;

// ─── Helper: sanitize nama file ─────────────────────────────────────────────

static void sanitize_name(const char* src, char* dst, size_t dsz) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dsz; i++) {
        char c = src[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '.') {
            dst[j++] = c;
        } else if (c == '/' || c == '\\') {
            dst[j++] = '_';
        }
    }
    dst[j] = '\0';
    if (j == 0) {
        snprintf(dst, dsz, "unknown_%d", g_dump_count);
    }
}

// ─── Hook: luaL_loadbuffer ──────────────────────────────────────────────────

static int hook_loadbuffer(lua_State* L,
                            const char* buff,
                            size_t sz,
                            const char* name)
{
    if (g_enabled && buff && sz > 0) {
        g_dump_count++;

        // Tentukan ekstensi: bytecode LuaJIT = "\x1bLJ", Lua plain = teks
        int is_bytecode = (sz >= 3 &&
                           (unsigned char)buff[0] == 0x1b &&
                           buff[1] == 'L' && buff[2] == 'J');

        // Bersihkan nama chunk (kadang diawali '@' = path file)
        const char* raw_name = name ? name : "chunk";
        if (raw_name[0] == '@') raw_name++;  // strip '@' prefix

        char safe_name[128];
        sanitize_name(raw_name, safe_name, sizeof(safe_name));

        // Timestamp singkat untuk hindari overwrite
        char ts[32];
        struct timespec tp;
        clock_gettime(CLOCK_MONOTONIC, &tp);
        snprintf(ts, sizeof(ts), "%ld", tp.tv_sec % 100000);

        // Path output
        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s/%s_%s%s",
                 DUMPDIR,
                 safe_name,
                 ts,
                 is_bytecode ? ".luajit" : ".lua");

        // Tulis file
        FILE* f = fopen(outpath, "wb");
        if (f) {
            fwrite(buff, 1, sz, f);
            fclose(f);
            logff_("[ScriptSpy] #%d dump: %s (%zu bytes, %s)",
                   g_dump_count, outpath, sz,
                   is_bytecode ? "bytecode" : "plaintext");
        } else {
            logff_("[ScriptSpy] #%d GAGAL tulis: %s", g_dump_count, outpath);
        }
    }

    // Panggil fungsi asli — tidak ada yang berubah di game
    return orig_loadbuffer(L, buff, sz, name);
}

// ─── API struct ─────────────────────────────────────────────────────────────

static void  _spy_enable(void)   { g_enabled = 1;  logf_("[ScriptSpy] enabled");  }
static void  _spy_disable(void)  { g_enabled = 0;  logf_("[ScriptSpy] disabled"); }
static int   _spy_is_on(void)    { return g_enabled; }
static int   _spy_count(void)    { return g_dump_count; }

struct ScriptSpyAPI {
    void (*enable)(void);
    void (*disable)(void);
    int  (*is_on)(void);
    int  (*count)(void);
};

// ─── AML entry points ────────────────────────────────────────────────────────

extern "C" {

EXPORT ScriptSpyAPI scriptspy_api = {
    _spy_enable,
    _spy_disable,
    _spy_is_on,
    _spy_count,
};

EXPORT void* __GetModInfo() {
    static const char* info =
        "scriptspy|1.0|Lua Script Dumper via luaL_loadbuffer hook|brruham";
    return (void*)info;
}

EXPORT void OnModPreLoad() {
    // Bersihkan log lama
    remove(LOGFILE);
    logf_("[ScriptSpy] OnModPreLoad v1.0");

    // Buat direktori dump jika belum ada
    mkdir(DUMPDIR, 0777);
}

EXPORT void OnModLoad() {
    logf_("[ScriptSpy] OnModLoad mulai");

    // ── Load Dobby ────────────────────────────────────────────────────────
    void* hDobby = dlopen("libdobby.so", RTLD_NOW | RTLD_GLOBAL);
    if (!hDobby) {
        logf_("[ScriptSpy] ERROR: libdobby.so tidak bisa dibuka");
        return;
    }
    logf_("[ScriptSpy] libdobby.so OK");

    auto resolver = (void*(*)(const char*, const char*))
                        dlsym(hDobby, "DobbySymbolResolver");
    auto dobbyHook = (int(*)(void*, void*, void**))
                        dlsym(hDobby, "DobbyHook");

    if (!resolver || !dobbyHook) {
        logf_("[ScriptSpy] ERROR: symbol Dobby tidak ditemukan");
        return;
    }
    logf_("[ScriptSpy] Dobby resolver + hook OK");

    // ── Resolve luaL_loadbuffer di libluajit-5.1.so ───────────────────────
    void* target = resolver("libluajit-5.1.so", "luaL_loadbuffer");
    if (!target) {
        logf_("[ScriptSpy] ERROR: luaL_loadbuffer tidak ditemukan");
        return;
    }
    logff_("[ScriptSpy] luaL_loadbuffer addr = %p", target);

    // ── Pasang hook ───────────────────────────────────────────────────────
    int ret = dobbyHook(
        target,
        (void*)hook_loadbuffer,
        (void**)&orig_loadbuffer
    );

    if (ret != 0 || !orig_loadbuffer) {
        logff_("[ScriptSpy] ERROR: DobbyHook gagal (ret=%d)", ret);
        return;
    }
    logf_("[ScriptSpy] Hook terpasang! Siap dump script.");

    // ── Simpan alamat API ke file untuk Lua bridge ────────────────────────
    FILE* af = fopen("/storage/emulated/0/scriptspy_addr.txt", "w");
    if (af) {
        fprintf(af, "%lu\n", (unsigned long)&scriptspy_api);
        fclose(af);
        logf_("[ScriptSpy] addr disimpan ke scriptspy_addr.txt");
    }

    logf_("[ScriptSpy] OnModLoad SELESAI");
}

} // extern "C"
