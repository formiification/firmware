#include "configuration.h"
#if !MESHTASTIC_EXCLUDE_NODELISTCMDS && !MESHTASTIC_EXCLUDE_PKI && !MESHTASTIC_EXCLUDE_TEXTMESSAGE
#include "NodeListCmdModule.h"
#include "MeshService.h"
#include "MessageStore.h"
#include "NodeDB.h"
#include "Throttle.h"
#include "UptimeClock.h"
#include "gps/RTC.h"
#include "main.h"
#include "mesh/AdminKeys.h"
#if !MESHTASTIC_EXCLUDE_NODEINFO
#include "modules/NodeInfoModule.h"
#endif

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Worst-case line "\n!xxxxxxxx SSSS 9999d" is 21 bytes; 9 lines plus the header stay under the PKI payload limit.
static constexpr uint16_t ENTRIES_PER_PAGE = 9;
static constexpr uint32_t PAGE_INTERVAL_MS = 6 * 1000;
static constexpr uint32_t LIST_COOLDOWN_MS = 10 * 1000;
static constexpr size_t MAX_REPLY_LEN = 200;

static bool matches(const meshtastic_NodeInfoLite *n, bool favorites)
{
    return favorites ? nodeInfoLiteIsFavorite(n) : nodeInfoLiteIsIgnored(n);
}

static size_t countMatching(bool favorites)
{
    size_t count = 0;
    for (size_t i = 0; i < nodeDB->getNumMeshNodes(); i++)
        if (matches(nodeDB->getMeshNodeByIndex(i), favorites))
            count++;
    return count;
}

static void formatAge(const meshtastic_NodeInfoLite *n, char *out, size_t outLen)
{
    if (n->last_heard == 0) {
        snprintf(out, outLen, "?");
        return;
    }
    uint32_t s = sinceLastSeen(n);
    if (s < 3600)
        snprintf(out, outLen, "%um", (unsigned)(s / 60));
    else if (s < 48 * 3600)
        snprintf(out, outLen, "%uh", (unsigned)(s / 3600));
    else
        snprintf(out, outLen, "%ud", (unsigned)(s / 86400 > 9999 ? 9999 : s / 86400));
}

static void formatShortName(const meshtastic_NodeInfoLite *n, char *out, size_t outLen)
{
    snprintf(out, outLen, "%s", n->short_name);
    for (char *c = out; *c; c++)
        if (*c == ' ' || *c == '\n' || *c == '\r' || *c == '\t')
            *c = '_';
    if (!*out)
        snprintf(out, outLen, "-");
}

// Strip leading blanks and test for an exact, case-insensitive command token; returns the rest or nullptr.
static const char *matchCommand(const char *msg, const char *cmd)
{
    size_t len = strlen(cmd);
    if (strncasecmp(msg, cmd, len) != 0)
        return nullptr;
    char next = msg[len];
    if (next != '\0' && !isspace((unsigned char)next))
        return nullptr;
    msg += len;
    while (*msg && isspace((unsigned char)*msg))
        msg++;
    return msg;
}

// Accepts "!a0eb6cc1" or "a0eb6cc1"; trailing blanks allowed.
static bool parseNodeId(const char *arg, NodeNum &out)
{
    if (*arg == '!')
        arg++;
    if (!isxdigit((unsigned char)*arg))
        return false;
    char *end = nullptr;
    unsigned long v = strtoul(arg, &end, 16);
    if (end - arg > 8)
        return false;
    while (*end && isspace((unsigned char)*end))
        end++;
    if (*end || v == 0)
        return false;
    out = (NodeNum)v;
    return true;
}

NodeListCmdModule::NodeListCmdModule()
    : SinglePortModule("nodelistcmd", meshtastic_PortNum_TEXT_MESSAGE_APP), concurrency::OSThread("NodeListCmd")
{
    setIntervalFromNow(INT32_MAX);
}

bool NodeListCmdModule::wantPacket(const meshtastic_MeshPacket *p)
{
    return p->decoded.portnum == ourPortNum && isToUs(p) && !isFromUs(p) && p->pki_encrypted && p->decoded.payload.size > 1 &&
           p->decoded.payload.bytes[0] == '!';
}

ProcessMessage NodeListCmdModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    if (mp.public_key.size != 32 || !AdminKeys::isAuthorized(mp.public_key.bytes))
        return ProcessMessage::CONTINUE;

    char buf[sizeof(mp.decoded.payload.bytes) + 1];
    size_t n = mp.decoded.payload.size;
    memcpy(buf, mp.decoded.payload.bytes, n);
    buf[n] = '\0';

    const char *arg;
    if ((arg = matchCommand(buf, "!list_favorites")))
        startList(mp, ListKind::FAVORITES, arg);
    else if ((arg = matchCommand(buf, "!list_ignored")))
        startList(mp, ListKind::IGNORED, arg);
    else if ((arg = matchCommand(buf, "!addfav")))
        handleFlag(mp, ListKind::FAVORITES, true, arg);
    else if ((arg = matchCommand(buf, "!unfav")))
        handleFlag(mp, ListKind::FAVORITES, false, arg);
    else if ((arg = matchCommand(buf, "!addign")))
        handleFlag(mp, ListKind::IGNORED, true, arg);
    else if ((arg = matchCommand(buf, "!unignore")) || (arg = matchCommand(buf, "!unign")))
        handleFlag(mp, ListKind::IGNORED, false, arg);
    else if ((arg = matchCommand(buf, "!nodeinfo")))
        handleNodeInfo(mp, arg);
    else if (matchCommand(buf, "!help"))
        sendText(mp.from, mp.public_key.bytes,
                 "!list_favorites [page]\n!list_ignored [page]\n!addfav ID\n!unfav ID\n!addign ID\n!unignore ID\n"
                 "!nodeinfo ID (exchange NodeInfo with ID)\n!help");

    return ProcessMessage::CONTINUE;
}

void NodeListCmdModule::startList(const meshtastic_MeshPacket &mp, ListKind kind, const char *arg)
{
    if (lastListFrom == mp.from && lastListMs && Throttle::isWithinTimespanMs(lastListMs, LIST_COOLDOWN_MS)) {
        LOG_INFO("NodeListCmd: list request from 0x%08x rate-limited", mp.from);
        return;
    }
    if (job.active && job.to != mp.from) {
        sendText(mp.from, mp.public_key.bytes, "BUSY, try again later");
        return;
    }

    const bool favorites = kind == ListKind::FAVORITES;
    const size_t total = countMatching(favorites);
    const uint16_t pages = total ? (total + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE : 1;

    uint16_t first = 0, last = pages - 1;
    if (*arg) {
        char *end = nullptr;
        long page = strtol(arg, &end, 10);
        if (end == arg || page < 1 || page > pages) {
            char msg[48];
            snprintf(msg, sizeof(msg), "%s no page %s (pages=%u)", favorites ? "FAV" : "IGN", arg, pages);
            sendText(mp.from, mp.public_key.bytes, msg);
            return;
        }
        first = last = (uint16_t)(page - 1);
    }

    lastListFrom = mp.from;
    lastListMs = Time::getMillis();
    LOG_INFO("NodeListCmd: %s pages %u-%u of %u to 0x%08x", favorites ? "favorites" : "ignored", first + 1, last + 1, pages,
             mp.from);

    job.active = true;
    job.to = mp.from;
    memcpy(job.key, mp.public_key.bytes, sizeof(job.key));
    job.kind = kind;
    job.nextPage = first;
    job.lastPage = last;
    setIntervalFromNow(0);
}

int32_t NodeListCmdModule::runOnce()
{
    if (!job.active)
        return INT32_MAX;

    const bool favorites = job.kind == ListKind::FAVORITES;
    // Recounted per page: the list may change between parts, the header shows what this part saw.
    const size_t total = countMatching(favorites);
    const uint16_t pages = total ? (total + ENTRIES_PER_PAGE - 1) / ENTRIES_PER_PAGE : 1;

    char out[MAX_REPLY_LEN + 1];
    int len = snprintf(out, sizeof(out), "%s %u/%u n=%u%s", favorites ? "FAV" : "IGN", job.nextPage + 1, pages, (unsigned)total,
                       getRTCQuality() == RTCQualityNone ? " clk?" : "");

    const size_t skip = (size_t)job.nextPage * ENTRIES_PER_PAGE;
    size_t seen = 0, listed = 0;
    for (size_t i = 0; i < nodeDB->getNumMeshNodes() && listed < ENTRIES_PER_PAGE; i++) {
        const meshtastic_NodeInfoLite *node = nodeDB->getMeshNodeByIndex(i);
        if (!matches(node, favorites) || seen++ < skip)
            continue;
        char name[sizeof(node->short_name)], age[8];
        formatShortName(node, name, sizeof(name));
        formatAge(node, age, sizeof(age));
        int w = snprintf(out + len, sizeof(out) - len, "\n!%08x %s %s", node->num, name, age);
        if (w < 0 || (size_t)(len + w) >= sizeof(out))
            break;
        len += w;
        listed++;
    }

    sendText(job.to, job.key, out);

    if (job.nextPage >= job.lastPage || job.nextPage + 1 >= pages) {
        job.active = false;
        return INT32_MAX;
    }
    job.nextPage++;
    return PAGE_INTERVAL_MS;
}

// Never let a remote command ignore us, the requester or another admin: ignored nodes' packets are dropped.
static bool isUnignorable(const meshtastic_MeshPacket &mp, NodeNum num)
{
    if (num == nodeDB->getNodeNum() || num == mp.from)
        return true;
    meshtastic_NodeInfoLite_public_key_t key = {0, {0}};
    return nodeDB->copyPublicKey(num, key) && key.size == 32 && AdminKeys::isAuthorized(key.bytes);
}

void NodeListCmdModule::handleFlag(const meshtastic_MeshPacket &mp, ListKind kind, bool set, const char *arg)
{
    const bool favorites = kind == ListKind::FAVORITES;
    const char *cmd = favorites ? (set ? "addfav" : "unfav") : (set ? "addign" : "unignore");
    const uint32_t mask = favorites ? NODEINFO_BITFIELD_IS_FAVORITE_MASK : NODEINFO_BITFIELD_IS_IGNORED_MASK;
    char msg[64];

    NodeNum num;
    if (!parseNodeId(arg, num)) {
        snprintf(msg, sizeof(msg), "BAD ID %s", arg);
        sendText(mp.from, mp.public_key.bytes, msg);
        return;
    }
    if (set && !favorites && isUnignorable(mp, num)) {
        snprintf(msg, sizeof(msg), "REFUSED addign !%08x (self/admin)", num);
        sendText(mp.from, mp.public_key.bytes, msg);
        return;
    }

    // Like the admin set_ignored_node, an ignore sticks even for a node we have not heard yet.
    meshtastic_NodeInfoLite *node = (set && !favorites) ? nodeDB->getOrCreateMeshNode(num) : nodeDB->getMeshNode(num);
    if (!node) {
        snprintf(msg, sizeof(msg), "NO NODE !%08x", num);
    } else if (matches(node, favorites) == set) {
        snprintf(msg, sizeof(msg), "%s %s !%08x", set ? "ALREADY" : "NOT", favorites ? "FAV" : "IGN", num);
    } else {
        if (set) {
            if (!nodeDB->setProtectedFlag(node, mask, true)) {
                snprintf(msg, sizeof(msg), "FULL %s !%08x: protected-node limit", cmd, num);
                sendText(mp.from, mp.public_key.bytes, msg);
                return;
            }
            if (!favorites) {
                nodeDB->eraseNodeSatellites(node->num);
#if HAS_SCREEN || defined(MESHTASTIC_INCLUDE_NICHE_GRAPHICS)
                messageStore.deleteAllMessagesFromNode(node->num);
#endif
            }
        } else {
            nodeInfoLiteSetBit(node, mask, false);
        }
        nodeDB->saveToDisk(SEGMENT_NODEDATABASE);
#if HAS_SCREEN
        if (screen)
            screen->setFrames(graphics::Screen::FOCUS_PRESERVE);
#endif
        LOG_INFO("NodeListCmd: %s 0x%08x by 0x%08x", cmd, num, mp.from);
        snprintf(msg, sizeof(msg), "OK %s !%08x", cmd, num);
    }
    sendText(mp.from, mp.public_key.bytes, msg);
}

void NodeListCmdModule::handleNodeInfo(const meshtastic_MeshPacket &mp, const char *arg)
{
    char msg[64];
    NodeNum num;
    if (!parseNodeId(arg, num) || num == nodeDB->getNodeNum() || num == NODENUM_BROADCAST) {
        snprintf(msg, sizeof(msg), "BAD ID %s", arg);
    }
#if MESHTASTIC_EXCLUDE_NODEINFO
    else {
        snprintf(msg, sizeof(msg), "NO NODEINFO MODULE");
    }
#else
    else if (!nodeInfoModule) {
        snprintf(msg, sizeof(msg), "NO NODEINFO MODULE");
    } else if (nodeInfoModule->sendOurNodeInfo(num, true, 0, true)) {
        LOG_INFO("NodeListCmd: nodeinfo to 0x%08x by 0x%08x", num, mp.from);
        snprintf(msg, sizeof(msg), "OK nodeinfo -> !%08x, reply requested", num);
    } else {
        // sendOurNodeInfo() holds back a repeat within 60 s and any send above the channel-utilisation cap.
        snprintf(msg, sizeof(msg), "SKIP nodeinfo -> !%08x (sent <60s ago or channel busy)", num);
    }
#endif
    sendText(mp.from, mp.public_key.bytes, msg);
}

void NodeListCmdModule::sendText(NodeNum to, const uint8_t *key, const char *text)
{
    meshtastic_MeshPacket *p = allocDataPacket();
    if (!p)
        return;
    p->to = to;
    p->channel = 0;
    p->want_ack = true;
    // Force PKI to the key that authorized the request, so a reply never falls back to a channel PSK.
    p->pki_encrypted = true;
    p->public_key.size = 32;
    memcpy(p->public_key.bytes, key, 32);
    size_t len = strnlen(text, sizeof(p->decoded.payload.bytes));
    memcpy(p->decoded.payload.bytes, text, len);
    p->decoded.payload.size = len;
    service->sendToMesh(p);
}

#endif
