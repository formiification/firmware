// What a CLIENT_BASE does with a frame it is waiting to rebroadcast when it overhears another node's
// rebroadcast of the same frame: FloodingRouter::roleAllowsCancelingDupe() and
// FloodingRouter::clientBaseRelaysLate() in src/mesh/FloodingRouter.cpp, reached through the real
// ingress pipeline so the duplicate arrives still encrypted, exactly as off the air.
//
// Why: a CLIENT_BASE is the rooftop node that carries traffic for weak indoor nodes (usually
// CLIENT_MUTE) behind it. The rebroadcast it overhears was heard by the roof antenna, not by those
// indoor nodes, so cancelling on it leaves them without the frame. For packets from or to its
// favorites it has always kept the relay; broadcast TEXT_MESSAGE_APP is kept too, because channel
// text from nodes that are not favorites otherwise never reaches the people indoors. Everything else
// still cancels like a CLIENT, so the base does not add airtime for telemetry and positions.
//
// Regressions guarded:
//   - channel text from a non-favorite is cancelled again on a CLIENT_BASE (the original bug); this
//     includes losing the portnum because the duplicate is not decoded when the decision is made;
//   - the exception leaking to other portnums, to unicast text, or to roles other than CLIENT_BASE;
//   - the favorite rule that predates the text exception being dropped while refactoring it.

#include "MeshTypes.h" // BEFORE TestUtil.h
#include "TestUtil.h"
#include <unity.h>

#include "support/AuthPipelineHarness.h"

static constexpr NodeNum STRANGER_NODE = 0x0E0E0E0E;

void setUp(void)
{
    pipelineHarnessSetUp();
    config.device.role = meshtastic_Config_DeviceConfig_Role_CLIENT_BASE;
}

void tearDown(void)
{
    pipelineHarnessTearDown();
}

static meshtastic_MeshPacket makeChannelPacket(NodeNum from, NodeNum to, meshtastic_PortNum port, PacketId id)
{
    meshtastic_MeshPacket p = makeDecoded(from, to, port, SMALL_PAYLOAD);
    p.id = id;
    p.hop_limit = 2;
    p.hop_start = 3;
    p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    return channelEncode(p);
}

// The base heard `p` first and queued its relay; now a neighbour's rebroadcast of it comes in.
// Returns whether the queued relay survived.
static bool relaySurvivesOverheardDupe(const meshtastic_MeshPacket &p)
{
    pipelineRouter->remember(&p);
    pipelineRadio->holdInTxQueue(getFrom(&p), p.id);
    runPipelineIngress(makeRelayedCopy(p));
    TEST_ASSERT_EQUAL_MESSAGE(1, pipelineRouter->rxDupe, "the relayed copy must be handled as a duplicate");
    return pipelineRadio->txQueueHolds(getFrom(&p), p.id);
}

void test_broadcast_text_from_stranger_is_still_relayed(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    const meshtastic_MeshPacket p =
        makeChannelPacket(STRANGER_NODE, NODENUM_BROADCAST, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x7E570001);

    TEST_ASSERT_TRUE_MESSAGE(relaySurvivesOverheardDupe(p),
                             "indoor nodes behind a CLIENT_BASE lose channel text if it cancels on an overheard relay");
    TEST_ASSERT_EQUAL(0, pipelineRadio->cancelCalls);
}

void test_broadcast_position_from_stranger_is_cancelled(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    const meshtastic_MeshPacket p =
        makeChannelPacket(STRANGER_NODE, NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x7E570002);

    TEST_ASSERT_FALSE_MESSAGE(relaySurvivesOverheardDupe(p), "only text is exempt; other broadcasts cancel like a CLIENT");
}

void test_unicast_text_between_strangers_is_cancelled(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    mockNodeDB->addNode(TARGET_NODE);
    const meshtastic_MeshPacket p =
        makeChannelPacket(STRANGER_NODE, TARGET_NODE, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x7E570003);

    TEST_ASSERT_FALSE_MESSAGE(relaySurvivesOverheardDupe(p), "the exemption is for broadcast text, not DMs between others");
}

void test_broadcast_text_on_client_role_is_cancelled(void)
{
    config.device.role = meshtastic_Config_DeviceConfig_Role_CLIENT;
    mockNodeDB->addNode(STRANGER_NODE);
    const meshtastic_MeshPacket p =
        makeChannelPacket(STRANGER_NODE, NODENUM_BROADCAST, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x7E570004);

    TEST_ASSERT_FALSE_MESSAGE(relaySurvivesOverheardDupe(p), "the text exemption belongs to CLIENT_BASE only");
}

void test_broadcast_position_from_favorite_is_still_relayed(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    nodeInfoLiteSetBit(mockNodeDB->getMeshNode(STRANGER_NODE), NODEINFO_BITFIELD_IS_FAVORITE_MASK, true);
    const meshtastic_MeshPacket p =
        makeChannelPacket(STRANGER_NODE, NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x7E570005);

    TEST_ASSERT_TRUE_MESSAGE(relaySurvivesOverheardDupe(p), "a favorite's traffic is relayed whatever its portnum");
}

void setup()
{
    pipelineHarnessCreate();
    UNITY_BEGIN();
    RUN_TEST(test_broadcast_text_from_stranger_is_still_relayed);
    RUN_TEST(test_broadcast_position_from_stranger_is_cancelled);
    RUN_TEST(test_unicast_text_between_strangers_is_cancelled);
    RUN_TEST(test_broadcast_text_on_client_role_is_cancelled);
    RUN_TEST(test_broadcast_position_from_favorite_is_still_relayed);
    const int result = UNITY_END();
    pipelineHarnessDestroy();
    exit(result);
}

void loop() {}
