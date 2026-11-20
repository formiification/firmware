#pragma once
#include "configuration.h"
#if !MESHTASTIC_EXCLUDE_NODELISTCMDS && !MESHTASTIC_EXCLUDE_PKI && !MESHTASTIC_EXCLUDE_TEXTMESSAGE
#include "SinglePortModule.h"
#include "concurrency/OSThread.h"

// PKI DM text commands from an admin key: !list_favorites|!list_ignored [page], !unfav|!unignore !nodeid.
// Everyone else is ignored silently; the text is always passed on to the other modules.
class NodeListCmdModule : public SinglePortModule, private concurrency::OSThread
{
  public:
    NodeListCmdModule();

  protected:
    bool wantPacket(const meshtastic_MeshPacket *p) override;
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
    int32_t runOnce() override;

  private:
    enum class ListKind : uint8_t { FAVORITES, IGNORED };

    // One page goes out per runOnce() so a long list doesn't flood the channel.
    struct ListJob {
        bool active = false;
        NodeNum to = 0;
        uint8_t key[32] = {0};
        ListKind kind = ListKind::FAVORITES;
        uint16_t nextPage = 0;
        uint16_t lastPage = 0;
    } job;

    uint32_t lastListMs = 0;
    NodeNum lastListFrom = 0;

    void startList(const meshtastic_MeshPacket &mp, ListKind kind, const char *arg);
    void handleClear(const meshtastic_MeshPacket &mp, ListKind kind, const char *arg);
    void sendText(NodeNum to, const uint8_t *key, const char *text);
};

#endif
