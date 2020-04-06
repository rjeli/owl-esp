#ifndef ENDIAN_H
#define ENDIAN_H

#include <stdint.h>

#define bswap16(x) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))
#define bswap32(x) ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) \
                  | (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#define bswap64(x) \
    ((((x) & 0xff00000000000000ull) >> 56) \
   | (((x) & 0x00ff000000000000ull) >> 40) \
   | (((x) & 0x0000ff0000000000ull) >> 24) \
   | (((x) & 0x000000ff00000000ull) >> 8) \
   | (((x) & 0x00000000ff000000ull) << 8) \
   | (((x) & 0x0000000000ff0000ull) << 24) \
   | (((x) & 0x000000000000ff00ull) << 40) \
   | (((x) & 0x00000000000000ffull) << 56))

#define htobe16(x) bswap16((x))
#define htole16(x) ((uint16_t)(x))
#define be16toh(x) bswap16((x))
#define le16toh(x) ((uint16_t)(x))

#define htobe32(x) bswap32((x))
#define htole32(x) ((uint32_t)(x))
#define be32toh(x) bswap32((x))
#define le32toh(x) ((uint32_t)(x))

#define htobe64(x) bswap64((x))
#define htole64(x) ((uint64_t)(x))
#define be64toh(x) bswap64((x))
#define le64toh(x) ((uint64_t)(x))

#endif // ENDIAN_H
