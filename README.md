# libscriptspy

AML mod untuk SA-MP Mobile (com.sampmobilerp.game) yang hook `luaL_loadbuffer`
di `libluajit-5.1.so` menggunakan Dobby — dump setiap Lua script yang di-load
MoNetLoader ke `/storage/emulated/0/ScriptSpy/`.

## Kegunaan
- Debug script Lua milik sendiri
- Lihat source script setelah di-load engine
- Analisa bytecode LuaJIT vs plaintext

## File Output
```
/storage/emulated/0/ScriptSpy/        ← dump semua script
/storage/emulated/0/scriptspy_log.txt ← log aktivitas
/storage/emulated/0/scriptspy_addr.txt← alamat API untuk Lua bridge
```

## Ekstensi Output
- `.lua`     → plaintext Lua (readable langsung)
- `.luajit`  → LuaJIT bytecode (perlu `luajit -bl` untuk disassemble)

## Install
1. Copy `libscriptspy.so` ke `/storage/emulated/0/Android/data/com.sampmobilerp.game/mods/`
2. Copy `scriptspy.lua` ke direktori MoNetLoader scripts
3. Jalankan game → script otomatis dump ke `ScriptSpy/`

## Kontrol In-Game (via scriptspy.lua)
```
/spy on      — aktifkan dumping
/spy off     — nonaktifkan dumping
/spy status  — lihat status + jumlah dump
/spy count   — jumlah script ter-dump
/spy reload  — reconnect API
```

## Build
Push ke GitHub → Actions otomatis build → download artifact `libscriptspy-arm32`.

## Requirements
- `libdobby.so` harus tersedia di AML
- `libluajit-5.1.so` harus ter-load oleh game
- Android 21+ (armeabi-v7a)

---
by brruham-arch
