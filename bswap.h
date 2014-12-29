#ifndef	__BSWAP_H__
#define	__BSWAP_H__

#include <endian.h>
#include <linux/types.h>

#ifdef __CHECKER__
#define __force    __attribute__((force))
#define __bitwise__ __attribute__((bitwise))
#else
#define __force
#define __bitwise__
#endif

#define le8_to_cpu(v) (v)
#define cpu_to_le8(v) (v)
#define __le8 uint8_t

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le64(x) ((__force __le64)(uint64_t)(bswap_64(x)))
#define le64_to_cpu(x) ((__force uint64_t)(__le64)(bswap_64(x)))
#define cpu_to_le32(x) ((__force __le32)(uint32_t)(bswap_32(x)))
#define le32_to_cpu(x) ((__force uint32_t)(__le32)(bswap_32(x)))
#define cpu_to_le16(x) ((__force __le16)(uint16_t)(bswap_16(x)))
#define le16_to_cpu(x) ((__force uint16_t)(__le16)(bswap_16(x)))
#else
#define cpu_to_le64(x) ((__force __le64)(uint64_t)(x))
#define le64_to_cpu(x) ((__force uint64_t)(__le64)(x))
#define cpu_to_le32(x) ((__force __le32)(uint32_t)(x))
#define le32_to_cpu(x) ((__force uint32_t)(__le32)(x))
#define cpu_to_le16(x) ((__force __le16)(uint16_t)(x))
#define le16_to_cpu(x) ((__force uint16_t)(__le16)(x))
#endif

#endif	/* __BSWAP_H__ */
