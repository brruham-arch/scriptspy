#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IAMI {
    void* (*GetLib)(const char* name);
    void  (*PlaceBranch)(uintptr_t at, uintptr_t to);
    void  (*Unprot)(uintptr_t at, size_t size);
    void  (*PlaceNOP)(uintptr_t at, size_t count);
    bool  (*GetCurrentGame)(char* buf, size_t sz);
} IAMI;

#ifdef __cplusplus
}
#endif
