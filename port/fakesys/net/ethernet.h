#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>

#define ETHER_ADDR_LEN 6
#define ETHER_MAX_LEN 1518

struct ether_addr {
    uint8_t ether_addr_octet[6];
};

#endif // ETHERNET_H
