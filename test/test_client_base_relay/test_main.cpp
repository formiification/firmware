// What a CLIENT_BASE does with a frame it is waiting to rebroadcast when it overhears another node's
// rebroadcast of the same frame: FloodingRouter::roleAllowsCancelingDupe(),
// FloodingRouter::clientBaseKeepsRelay() and FloodingRouter::perhapsCancelDupe() in
// src/mesh/FloodingRouter.cpp, plus the window it first schedules the relay in,
// RadioInterface::shouldRebroadcastEarlyLikeRouter(). The duplicate goes through the real ingress
// pipeline so it arrives still encrypted, exactly as off the air.
//
// Why: a CLIENT_BASE is the rooftop node that carries traffic for weak indoor nodes (usually
// CLIENT_MUTE) behind it. The rebroadcast it overhears was heard by the roof antenna, not by those
// indoor nodes, so cancelling on it leaves them without the frame. For packets from or to its
// favorites it has always kept the relay; broadcast TEXT_MESSAGE_APP is kept too, because channel
// text from nodes that are not favorites otherwise never reaches the people indoors. Everything else
// still cancels like a CLIENT, so the base does not add airtime for telemetry and positions.
//
// Which window a kept relay goes out in depends on whether it floods. A kept broadcast moves to the
// late window when a duplicate is heard, so the base still yields to nodes that relayed earlier. A
// unicast from or to a favorite follows one path: it is scheduled in the early (ROUTER) window and
// never moved late, because the late window sits behind every other relay in the TX queue and a
// traceroute from a favorite was seen waiting there for over two minutes.
//
// Regressions guarded:
//   - channel text from a non-favorite is cancelled again on a CLIENT_BASE (the original bug); this
//     includes losing the portnum because the duplicate is not decoded when the decision is made;
//   - the exception leaking to other portnums, to unicast text, or to roles other than CLIENT_BASE;
//   - the favorite rule that predates the text exception being dropped while refactoring it;
//   - a favorite's unicast scheduled in the CLIENT window or moved to the late window again;
//   - the early window leaking to broadcasts from favorites or to unicast between strangers.

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

void test_unicast_from_favorite_is_relayed_early_and_never_moved_late(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    mockNodeDB->addNode(TARGET_NODE);
    nodeInfoLiteSetBit(mockNodeDB->getMeshNode(STRANGER_NODE), NODEINFO_BITFIELD_IS_FAVORITE_MASK, true);
    meshtastic_MeshPacket p = makeChannelPacket(STRANGER_NODE, TARGET_NODE, meshtastic_PortNum_TRACEROUTE_APP, 0x7E570006);

    TEST_ASSERT_TRUE_MESSAGE(pipelineRadio->shouldRebroadcastEarlyLikeRouter(&p),
                             "a favorite's unicast is scheduled in the ROUTER window");
    TEST_ASSERT_TRUE_MESSAGE(relaySurvivesOverheardDupe(p), "a favorite's unicast is still never cancelled");
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineRadio->lateClampCalls,
                              "the late window parks the relay behind every other one in the TX queue");
}

void test_unicast_to_favorite_is_relayed_early(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    mockNodeDB->addNode(TARGET_NODE);
    nodeInfoLiteSetBit(mockNodeDB->getMeshNode(TARGET_NODE), NODEINFO_BITFIELD_IS_FAVORITE_MASK, true);
    meshtastic_MeshPacket p = makeChannelPacket(STRANGER_NODE, TARGET_NODE, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x7E570007);

    TEST_ASSERT_TRUE(pipelineRadio->shouldRebroadcastEarlyLikeRouter(&p));
    TEST_ASSERT_TRUE(relaySurvivesOverheardDupe(p));
    TEST_ASSERT_EQUAL(0, pipelineRadio->lateClampCalls);
}

void test_broadcast_from_favorite_still_moves_to_late_window(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    nodeInfoLiteSetBit(mockNodeDB->getMeshNode(STRANGER_NODE), NODEINFO_BITFIELD_IS_FAVORITE_MASK, true);
    meshtastic_MeshPacket p = makeChannelPacket(STRANGER_NODE, NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x7E570008);

    TEST_ASSERT_FALSE_MESSAGE(pipelineRadio->shouldRebroadcastEarlyLikeRouter(&p),
                              "a broadcast floods, so the base must not relay it in the ROUTER window");
    TEST_ASSERT_TRUE(relaySurvivesOverheardDupe(p));
    TEST_ASSERT_EQUAL_MESSAGE(1, pipelineRadio->lateClampCalls, "a kept broadcast yields to nodes that relayed earlier");
}

void test_broadcast_text_from_stranger_moves_to_late_window(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    meshtastic_MeshPacket p =
        makeChannelPacket(STRANGER_NODE, NODENUM_BROADCAST, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x7E570009);

    TEST_ASSERT_FALSE(pipelineRadio->shouldRebroadcastEarlyLikeRouter(&p));
    TEST_ASSERT_TRUE(relaySurvivesOverheardDupe(p));
    TEST_ASSERT_EQUAL(1, pipelineRadio->lateClampCalls);
}

void test_unicast_between_strangers_uses_client_window(void)
{
    mockNodeDB->addNode(STRANGER_NODE);
    mockNodeDB->addNode(TARGET_NODE);
    meshtastic_MeshPacket p = makeChannelPacket(STRANGER_NODE, TARGET_NODE, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x7E57000A);

    TEST_ASSERT_FALSE_MESSAGE(pipelineRadio->shouldRebroadcastEarlyLikeRouter(&p),
                              "the early window is for a favorite's unicast only");
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
    RUN_TEST(test_unicast_from_favorite_is_relayed_early_and_never_moved_late);
    RUN_TEST(test_unicast_to_favorite_is_relayed_early);
    RUN_TEST(test_broadcast_from_favorite_still_moves_to_late_window);
    RUN_TEST(test_broadcast_text_from_stranger_moves_to_late_window);
    RUN_TEST(test_unicast_between_strangers_uses_client_window);
    const int result = UNITY_END();
    pipelineHarnessDestroy();
    exit(result);
}

void loop() {}
