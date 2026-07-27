// Minimal lwIP type stub for host-side tests. Only what wireguard.h consumes.
#ifndef FAKE_LWIP_ARCH_H
#define FAKE_LWIP_ARCH_H
#include <stdint.h>
typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uint64_t u64_t;
#endif
