#include "UdpPeers.h"

#if HAS_UDP_UNICAST_PEERS
#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <freertos/FreeRTOS.h>
#include <lwip/dhcp.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/prot/dhcp.h>
#include <lwip_default_hooks.h>
#include <stdio.h>
#include <string.h>

namespace udppeers
{

namespace
{
constexpr uint8_t DHCP_OPTION_VENDOR_SPECIFIC = 43;
constexpr uint8_t SUBOPT_ADDRESSES = 1;
constexpr uint8_t SUBOPT_PORT = 2;
constexpr const char *VENDOR_CLASS = "meshtastic";
constexpr uint8_t SOURCE_SLOTS = 32;

struct Lease {
    const struct dhcp *dhcp; // identifies the interface
    uint32_t xid;            // kept by lwIP on renew/rebind, new on DISCOVER and INIT-REBOOT
    PeerList peers;
};

struct Source {
    uint32_t from;
    uint32_t id;
    uint32_t peer;
};

portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
Lease lease;
Source sources[SOURCE_SLOTS];
uint8_t nextSource;
uint32_t seen43;    // diag
uint8_t lastRawLen; // diag
const char *reason = "no option 43 yet";

bool isAckState(uint8_t state)
{
    return state == DHCP_STATE_REQUESTING || state == DHCP_STATE_REBOOTING || state == DHCP_STATE_RENEWING ||
           state == DHCP_STATE_REBINDING;
}

void parse(const uint8_t *buf, uint8_t len, PeerList &out)
{
    out.count = 0;
    out.port = DEFAULT_PORT;
    for (uint16_t i = 0; i + 2 <= len;) {
        uint8_t code = buf[i];
        if (code == 0) { // pad
            i++;
            continue;
        }
        if (code == 255)
            break;
        uint8_t sublen = buf[i + 1];
        const uint8_t *data = buf + i + 2;
        if (i + 2 + sublen > len)
            break;
        if (code == SUBOPT_ADDRESSES && sublen % 4 == 0) {
            for (uint8_t j = 0; j < sublen && out.count < MAX_PEERS; j += 4) {
                uint32_t a;
                memcpy(&a, data + j, 4); // wire order == lwIP order
                bool dup = false;
                for (uint8_t k = 0; k < out.count; k++)
                    dup |= out.addr[k] == a;
                if (!dup && isPrivate(a))
                    out.addr[out.count++] = a;
            }
        } else if (code == SUBOPT_PORT && sublen == 2) {
            uint16_t p = (uint16_t(data[0]) << 8) | data[1];
            if (p)
                out.port = p;
        }
        i += 2 + sublen;
    }
}
} // namespace

bool isPrivate(uint32_t addr)
{
    const uint8_t *b = reinterpret_cast<const uint8_t *>(&addr);
    return b[0] == 10 || (b[0] == 172 && (b[1] & 0xF0) == 16) || (b[0] == 192 && b[1] == 168);
}

void setVendorClass()
{
#if !CONFIG_LWIP_DHCP_DISABLE_VENDOR_CLASS_ID
    dhcp_set_vendor_class_identifier(strlen(VENDOR_CLASS), VENDOR_CLASS);
#endif
}

bool get(PeerList &out)
{
    Lease l;
    portENTER_CRITICAL(&mux);
    l = lease;
    portEXIT_CRITICAL(&mux);
    out.count = 0;
    out.port = l.peers.port;
    if (!l.dhcp) {
        reason = "no option 43 yet";
        return false;
    }
    if (!l.peers.count) {
        reason = "option 43 had no usable addresses";
        return false;
    }

    struct netif *nif = nullptr;
    for (const char *key : {"WIFI_STA_DEF", "ETH_DEF"}) {
        esp_netif_t *en = esp_netif_get_handle_from_ifkey(key);
        struct netif *n = en ? static_cast<struct netif *>(esp_netif_get_netif_impl(en)) : nullptr;
        if (n && netif_dhcp_data(n) == l.dhcp) {
            nif = n;
            break;
        }
    }
    if (!nif) {
        reason = "lease from unknown interface";
        return false;
    }
    if (!dhcp_supplied_address(nif)) {
        reason = "interface not bound";
        return false;
    }
    if (netif_dhcp_data(nif)->xid != l.xid) {
        reason = "lease without option 43 since";
        return false;
    }

    uint32_t self = ip4_addr_get_u32(netif_ip4_addr(nif));
    for (uint8_t i = 0; i < l.peers.count; i++)
        if (l.peers.addr[i] != self)
            out.addr[out.count++] = l.peers.addr[i];
    reason = out.count ? "ok" : "only our own address";
    return out.count > 0;
}

void diag(char *buf, size_t len)
{
    snprintf(buf, len, "%s; option 43 seen %u times, last %u bytes", reason, (unsigned)seen43, lastRawLen);
}

void noteSource(uint32_t from, uint32_t id, uint32_t peerAddr)
{
    portENTER_CRITICAL(&mux);
    sources[nextSource] = {from, id, peerAddr};
    nextSource = (nextSource + 1) % SOURCE_SLOTS;
    portEXIT_CRITICAL(&mux);
}

uint32_t sourceOf(uint32_t from, uint32_t id)
{
    uint32_t peer = 0;
    portENTER_CRITICAL(&mux);
    for (const Source &s : sources)
        if (s.peer && s.from == from && s.id == id)
            peer = s.peer;
    portEXIT_CRITICAL(&mux);
    return peer;
}

} // namespace udppeers

// Runs in the tcpip thread for every DHCP option lwIP itself does not handle.
extern "C" void lwip_dhcp_on_extra_option(struct dhcp *dhcp, uint8_t state, uint8_t option, uint8_t len, struct pbuf *p,
                                          uint16_t offset)
{
    using namespace udppeers;
    if (option != DHCP_OPTION_VENDOR_SPECIFIC || !isAckState(state))
        return;
    uint8_t buf[255];
    if (pbuf_copy_partial(p, buf, len, offset) != len)
        return;
    seen43++;
    lastRawLen = len;
    Lease l;
    l.dhcp = dhcp;
    l.xid = dhcp->xid;
    parse(buf, len, l.peers);
    portENTER_CRITICAL(&mux);
    lease = l;
    portEXIT_CRITICAL(&mux);
}
#endif
