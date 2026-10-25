// Unit tests for the late-window handling in MeshPacketQueue: replaceLowerPriorityPacket()'s
// late-packet branch - the one that evicts an overdue packet from a full queue to make room for a
// new arrival - and promoteOverdue(), which puts an overdue late packet back into priority order.
//
// tx_after is an absolute millis() deadline, so every decision here has to subtract before comparing
// or it inverts across the 32-bit wrap. The subtlety the cases below pin is that an *elapsed* time
// only orders two deadlines that have both passed: a deadline still in the future subtracts to a
// near-2^32 elapsed, which reads as the most overdue packet in the queue rather than the least.
//
// The eviction cases use maxLen 1. That is enough to reach the branch (any enqueue into a full queue
// goes through it) and it keeps CompareMeshPacketFunc out of the picture - std::upper_bound over an
// empty range never invokes the comparator.
//
// The promotion cases need a longer queue, so the comparator runs. Every packet keeps from == 0,
// which isFromUs() answers before it reads nodeDB, so the suite still needs no NodeDB.
//
// Why promotion exists: CompareMeshPacketFunc puts every packet with tx_after behind every packet
// without, whatever their priorities, and the radio only ever sends the front of the queue. A node
// that keeps relaying fresh traffic therefore never reaches a late packet, even long after its
// deadline. A CLIENT_BASE was seen holding a favorite's traceroute there for 133 s on SHORT_FAST,
// where the whole late window is under 5 s.

#include "Arduino.h"
#include "TestUtil.h"
#include "UptimeClock.h"
#include "configuration.h"
#include "mesh/MeshPacketQueue.h"
#include "mesh/MeshTypes.h"
#include <cstdlib>
#include <unity.h>

namespace
{

// A packet that is only ever a queue occupant: id and tx_after are all the branch reads.
meshtastic_MeshPacket *makePacket(uint32_t id, uint32_t txAfter)
{
    meshtastic_MeshPacket *p = packetPool.allocZeroed();
    TEST_ASSERT_NOT_NULL(p);
    p->id = id;
    p->tx_after = txAfter;
    p->priority = meshtastic_MeshPacket_Priority_DEFAULT;
    return p;
}

meshtastic_MeshPacket *makePacket(uint32_t id, uint32_t txAfter, meshtastic_MeshPacket_Priority priority)
{
    meshtastic_MeshPacket *p = makePacket(id, txAfter);
    p->priority = priority;
    return p;
}

// Drains whatever is still queued back to the pool, so a failing case cannot starve a later one.
void drain(MeshPacketQueue &q)
{
    while (meshtastic_MeshPacket *p = q.dequeue())
        packetPool.release(p);
}

} // namespace

void setUp(void)
{
    Time::setTestMillis(0);
}
void tearDown(void)
{
    Time::useRealClock();
}

// The regression: the incoming packet is not due yet, so it must not displace an overdue one.
// `now - p->tx_after` underflows to ~49.7 days of "elapsed", which an unguarded comparison reads as
// the more urgent packet.
static void test_future_incoming_deadline_does_not_evict_an_overdue_packet(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(1);

    meshtastic_MeshPacket *back = makePacket(0x1001, 900);   // 100ms overdue
    meshtastic_MeshPacket *fresh = makePacket(0x1002, 1100); // 100ms in the future
    TEST_ASSERT_TRUE(q.enqueue(back));

    TEST_ASSERT_FALSE(q.enqueue(fresh));
    TEST_ASSERT_EQUAL_HEX32(0x1001, q.getFront()->id);

    packetPool.release(fresh);
    drain(q);
}

// The ordering the branch does want: both deadlines have passed and the arrival is the more overdue
// of the two, so the queued packet gives up its slot.
static void test_more_overdue_incoming_packet_evicts_the_late_back_packet(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(1);

    meshtastic_MeshPacket *back = makePacket(0x2001, 900);  // 100ms overdue
    meshtastic_MeshPacket *fresh = makePacket(0x2002, 800); // 200ms overdue
    TEST_ASSERT_TRUE(q.enqueue(back));

    TEST_ASSERT_TRUE(q.enqueue(fresh)); // back is released by the queue
    TEST_ASSERT_EQUAL_HEX32(0x2002, q.getFront()->id);

    drain(q);
}

// The other half of that ordering: a less overdue arrival leaves the queue alone.
static void test_less_overdue_incoming_packet_is_rejected(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(1);

    meshtastic_MeshPacket *back = makePacket(0x3001, 800);  // 200ms overdue
    meshtastic_MeshPacket *fresh = makePacket(0x3002, 900); // 100ms overdue
    TEST_ASSERT_TRUE(q.enqueue(back));

    TEST_ASSERT_FALSE(q.enqueue(fresh));
    TEST_ASSERT_EQUAL_HEX32(0x3001, q.getFront()->id);

    packetPool.release(fresh);
    drain(q);
}

// An arrival with no TX delay at all always wins the slot from an overdue packet.
static void test_undelayed_incoming_packet_evicts_the_late_back_packet(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(1);

    meshtastic_MeshPacket *back = makePacket(0x4001, 900);
    meshtastic_MeshPacket *fresh = makePacket(0x4002, 0); // no tx_after
    TEST_ASSERT_TRUE(q.enqueue(back));

    TEST_ASSERT_TRUE(q.enqueue(fresh));
    TEST_ASSERT_EQUAL_HEX32(0x4002, q.getFront()->id);

    drain(q);
}

// Both deadlines were set before the wrap and `now` is after it, so every raw comparison in the
// branch inverts. The decisions must come out the same as they do away from the boundary.
static void test_decisions_survive_the_millis_wrap(void)
{
    // 0xFFFFFF00 and 0xFFFFFE00 are 256ms and 512ms before the wrap; now is 256ms after it.
    Time::setTestMillis(0x00000100);
    MeshPacketQueue q(1);

    meshtastic_MeshPacket *back = makePacket(0x5001, 0xFFFFFF00);  // 512ms overdue
    meshtastic_MeshPacket *older = makePacket(0x5002, 0xFFFFFE00); // 768ms overdue
    TEST_ASSERT_TRUE(q.enqueue(back));
    TEST_ASSERT_TRUE(q.enqueue(older));
    TEST_ASSERT_EQUAL_HEX32(0x5002, q.getFront()->id);
    drain(q);

    // ...and a not-yet-due arrival still loses, with the deadline on the far side of the wrap.
    MeshPacketQueue q2(1);
    meshtastic_MeshPacket *back2 = makePacket(0x5003, 0xFFFFFF00); // 512ms overdue
    meshtastic_MeshPacket *fresh = makePacket(0x5004, 0x00000300); // 512ms in the future
    TEST_ASSERT_TRUE(q2.enqueue(back2));

    TEST_ASSERT_FALSE(q2.enqueue(fresh));
    TEST_ASSERT_EQUAL_HEX32(0x5003, q2.getFront()->id);

    packetPool.release(fresh);
    drain(q2);
}

// Once its deadline has passed, a late packet is no longer parked behind lower-priority traffic.
static void test_overdue_late_packet_is_promoted_into_priority_order(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(4);

    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x6001, 900, meshtastic_MeshPacket_Priority_RELIABLE))); // 100ms overdue
    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x6002, 0, meshtastic_MeshPacket_Priority_DEFAULT)));
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x6002, q.getFront()->id, "a late packet waits behind every undelayed one");

    TEST_ASSERT_EQUAL(1, q.promoteOverdue(1000));
    meshtastic_MeshPacket *front = q.getFront();
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x6001, front->id, "once overdue it competes by priority");
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, front->tx_after, "a promoted packet is no longer in the late window");

    drain(q);
}

// The late window itself is untouched: a packet still inside it keeps yielding.
static void test_late_packet_inside_its_window_stays_at_the_back(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(4);

    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x7001, 1100, meshtastic_MeshPacket_Priority_RELIABLE))); // due in 100ms
    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x7002, 0, meshtastic_MeshPacket_Priority_DEFAULT)));

    TEST_ASSERT_EQUAL(0, q.promoteOverdue(1000));
    TEST_ASSERT_EQUAL_HEX32(0x7002, q.getFront()->id);
    TEST_ASSERT_EQUAL_UINT32(1100, q.getPacketFromQueue(0, 0x7001)->tx_after);

    drain(q);
}

// The starvation itself: one fresh equal-priority relay arrives for every one sent. Promoted, the
// overdue packet goes out after the relays already queued when it became due (0x8000 and 0x8001),
// not after every later one. Without promotion it would never reach the front.
static void test_stream_of_fresh_relays_cannot_starve_an_overdue_packet(void)
{
    Time::setTestMillis(1000);
    MeshPacketQueue q(16);

    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x8000, 0, meshtastic_MeshPacket_Priority_DEFAULT)));
    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x8FFF, 900, meshtastic_MeshPacket_Priority_DEFAULT))); // overdue

    int sentAt = -1;
    for (int i = 0; i < 100 && sentAt < 0; i++) {
        TEST_ASSERT_TRUE(q.enqueue(makePacket(0x8001 + i, 0, meshtastic_MeshPacket_Priority_DEFAULT)));
        q.promoteOverdue(1000);
        meshtastic_MeshPacket *sent = q.dequeue();
        if (sent->id == 0x8FFF)
            sentAt = i;
        packetPool.release(sent);
    }
    TEST_ASSERT_EQUAL_MESSAGE(2, sentAt, "the overdue packet must go out right after the relays queued before it");

    drain(q);
}

// Promotion compares deadlines the same wrap-safe way as the eviction branch.
static void test_promotion_survives_the_millis_wrap(void)
{
    Time::setTestMillis(0x00000100);
    MeshPacketQueue q(4);

    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x9001, 0xFFFFFF00, meshtastic_MeshPacket_Priority_RELIABLE))); // 512ms overdue
    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x9002, 0x00000300, meshtastic_MeshPacket_Priority_RELIABLE))); // due in 512ms
    TEST_ASSERT_TRUE(q.enqueue(makePacket(0x9003, 0, meshtastic_MeshPacket_Priority_DEFAULT)));

    TEST_ASSERT_EQUAL(1, q.promoteOverdue(0x00000100));
    meshtastic_MeshPacket *first = q.dequeue();
    TEST_ASSERT_EQUAL_HEX32(0x9001, first->id);
    packetPool.release(first);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(0x9003, q.getFront()->id, "the packet still inside its window keeps yielding");

    drain(q);
}

void setup()
{
    delay(10);
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_future_incoming_deadline_does_not_evict_an_overdue_packet);
    RUN_TEST(test_more_overdue_incoming_packet_evicts_the_late_back_packet);
    RUN_TEST(test_less_overdue_incoming_packet_is_rejected);
    RUN_TEST(test_undelayed_incoming_packet_evicts_the_late_back_packet);
    RUN_TEST(test_decisions_survive_the_millis_wrap);
    RUN_TEST(test_overdue_late_packet_is_promoted_into_priority_order);
    RUN_TEST(test_late_packet_inside_its_window_stays_at_the_back);
    RUN_TEST(test_stream_of_fresh_relays_cannot_starve_an_overdue_packet);
    RUN_TEST(test_promotion_survives_the_millis_wrap);
    exit(UNITY_END());
}

void loop() {}
