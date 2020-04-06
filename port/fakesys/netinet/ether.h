#ifndef ETHER_H
#define ETHER_H

#include <net/ethernet.h>

char *ether_ntoa(const struct ether_addr *addr);

#endif // ETHER_H
