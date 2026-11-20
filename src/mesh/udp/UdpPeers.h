#pragma once
// Unicast UDP peers from DHCP option 43 (sub 1: IPv4 list, sub 2: port); node
// sends option 60 "meshtastic".

#include "configuration.h"

#if defined(ARCH_ESP32) && defined(HAS_UDP_MULTICAST) && HAS_UDP_MULTICAST
#include "sdkconfig.h"
#if defined(CONFIG_LWIP_HOOK_DHCP_EXTRA_OPTION_CUSTOM)
#define HAS_UDP_UNICAST_PEERS 1
#endif
#endif

#if HAS_UDP_UNICAST_PEERS
#include <stddef.h>
#include <stdint.h>

namespace udppeers
{

constexpr uint8_t MAX_PEERS = 16;
constexpr uint16_t DEFAULT_PORT = 4403;

struct PeerList {
    uint32_t addr[MAX_PEERS]; // lwIP byte order, as in ip4_addr_t.addr
    uint8_t count;
    uint16_t port;
};

// Must run before the interface starts DHCP.
void setVendorClass();

// Peers from the lease the interface is bound with, minus our own address;
// false when none.
bool get(PeerList &out);

bool isPrivate(uint32_t addr);

void diag(char *buf, size_t len);

// Split horizon: never send a packet back to the peer it arrived from.
void noteSource(uint32_t from, uint32_t id, uint32_t peerAddr);
uint32_t sourceOf(uint32_t from, uint32_t id);

} // namespace udppeers
#endif
