// What a node does with a broadcast that asks for replies (Data.want_response, or the want_response
// bit in Data.bitfield): the drop in Router::dispatchReceived() in src/mesh/Router.cpp, reached
// through the real ingress pipeline so the frame arrives encrypted, exactly as off the air.
//
// Why: one broadcast with want_response makes every node that hears it answer, so a single frame
// can trigger a storm of replies across the mesh. The node must neither act on it nor relay it.
//
// Regressions guarded:
//   - the broadcast is relayed, handed to modules or queued for the phone;
//   - the bitfield form of the flag slipping past the check;
//   - the drop leaking to broadcasts without the flag or to unicast requests (a normal position or
//     nodeinfo request to one node must still be carried);
//   - a relay already queued from an earlier copy without the flag not being cancelled.

#include "MeshTypes.h" // BEFORE TestUtil.h
#include "TestUtil.h"
#include <unity.h>

#include "support/AuthPipelineHarness.h"

static constexpr NodeNum STRANGER_NODE = 0x0E0E0E0E;

void setUp(void)
{
    pipelineHarnessSetUp();
    config.device.role = meshtastic_Config_DeviceConfig_Role_CLIENT;
    mockNodeDB->addNode(STRANGER_NODE);
}

void tearDown(void)
{
    pipelineHarnessTearDown();
}

enum class Flag { NONE, FIELD, BITFIELD };

static meshtastic_MeshPacket makeRequest(NodeNum to, meshtastic_PortNum port, PacketId id, Flag flag)
{
    meshtastic_MeshPacket p = makeDecoded(STRANGER_NODE, to, port, SMALL_PAYLOAD);
    p.id = id;
    p.hop_limit = 2;
    p.hop_start = 3;
    p.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    if (flag == Flag::FIELD)
        p.decoded.want_response = true;
    if (flag == Flag::BITFIELD) {
        p.decoded.has_bitfield = true;
        p.decoded.bitfield = BITFIELD_WANT_RESPONSE_MASK;
    }
    return channelEncode(p);
}

static void expectDropped(const meshtastic_MeshPacket &p, const char *why)
{
    runPipelineIngress(p);
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineRadio->sendCalls, why);
    TEST_ASSERT_EQUAL_MESSAGE(0, pipelineModule->calls, "a dropped request must not reach modules");
    TEST_ASSERT_EQUAL_MESSAGE(0, drainPhoneQueue(), "a dropped request must not reach the phone");
}

void test_broadcast_text_with_want_response_is_not_relayed(void)
{
    expectDropped(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x5EED0001, Flag::FIELD),
                  "broadcast text with want_response must not be relayed");
}

void test_broadcast_position_with_want_response_is_not_relayed(void)
{
    expectDropped(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x5EED0002, Flag::FIELD),
                  "a broadcast position request would make every node answer");
}

void test_broadcast_nodeinfo_with_want_response_is_not_relayed(void)
{
    expectDropped(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_NODEINFO_APP, 0x5EED0003, Flag::FIELD),
                  "a broadcast nodeinfo request would make every node answer");
}

void test_broadcast_with_want_response_bitfield_is_not_relayed(void)
{
    expectDropped(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x5EED0004, Flag::BITFIELD),
                  "the bitfield form of want_response must be dropped too");
}

void test_broadcast_with_want_response_is_dropped_on_router_role(void)
{
    config.device.role = meshtastic_Config_DeviceConfig_Role_ROUTER;
    expectDropped(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x5EED0005, Flag::FIELD),
                  "a ROUTER must not carry it either");
}

void test_broadcast_with_want_response_is_dropped_on_client_base_role(void)
{
    config.device.role = meshtastic_Config_DeviceConfig_Role_CLIENT_BASE;
    expectDropped(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_TEXT_MESSAGE_APP, 0x5EED0006, Flag::FIELD),
                  "the CLIENT_BASE text exemption must not carry a want_response broadcast");
}

void test_broadcast_without_want_response_is_relayed(void)
{
    runPipelineIngress(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, 0x5EED0007, Flag::NONE));
    drainPhoneQueue();
    TEST_ASSERT_EQUAL_MESSAGE(1, pipelineRadio->sendCalls, "an ordinary broadcast is still relayed");
    TEST_ASSERT_EQUAL(1, pipelineModule->calls);
}

void test_unicast_request_to_another_node_is_relayed(void)
{
    mockNodeDB->addNode(TARGET_NODE);
    runPipelineIngress(makeRequest(TARGET_NODE, meshtastic_PortNum_POSITION_APP, 0x5EED0008, Flag::FIELD));
    drainPhoneQueue();
    TEST_ASSERT_EQUAL_MESSAGE(1, pipelineRadio->sendCalls, "a unicast request between other nodes is still carried");
}

void test_queued_relay_is_cancelled_by_want_response_copy(void)
{
    const PacketId id = 0x5EED0009;
    pipelineRadio->holdInTxQueue(STRANGER_NODE, id);
    runPipelineIngress(makeRequest(NODENUM_BROADCAST, meshtastic_PortNum_POSITION_APP, id, Flag::FIELD));
    TEST_ASSERT_FALSE_MESSAGE(pipelineRadio->txQueueHolds(STRANGER_NODE, id), "a pending relay of the frame must be cancelled");
    TEST_ASSERT_EQUAL(0, pipelineRadio->sendCalls);
}

void setup()
{
    pipelineHarnessCreate();
    UNITY_BEGIN();
    RUN_TEST(test_broadcast_text_with_want_response_is_not_relayed);
    RUN_TEST(test_broadcast_position_with_want_response_is_not_relayed);
    RUN_TEST(test_broadcast_nodeinfo_with_want_response_is_not_relayed);
    RUN_TEST(test_broadcast_with_want_response_bitfield_is_not_relayed);
    RUN_TEST(test_broadcast_with_want_response_is_dropped_on_router_role);
    RUN_TEST(test_broadcast_with_want_response_is_dropped_on_client_base_role);
    RUN_TEST(test_broadcast_without_want_response_is_relayed);
    RUN_TEST(test_unicast_request_to_another_node_is_relayed);
    RUN_TEST(test_queued_relay_is_cancelled_by_want_response_copy);
    const int result = UNITY_END();
    pipelineHarnessDestroy();
    exit(result);
}

void loop() {}
