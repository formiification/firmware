// devicestate.my_node survives a firmware reinstall, so a build must stamp its own edition over a persisted event
// edition at boot: USERPREFS_FIRMWARE_EDITION when set, otherwise this fork's default, DIY_EDITION.
#include "MeshTypes.h" // Include BEFORE TestUtil.h
#include "TestUtil.h"
#include "mesh/NodeDB.h"
#include <unity.h>

#if defined(ARCH_PORTDUINO)
#define FE_TEST_ENTRY extern "C"
#else
#define FE_TEST_ENTRY
#endif

#ifdef USERPREFS_FIRMWARE_EDITION
static const meshtastic_FirmwareEdition expectedEdition = USERPREFS_FIRMWARE_EDITION;
#else
static const meshtastic_FirmwareEdition expectedEdition = meshtastic_FirmwareEdition_DIY_EDITION;
#endif

void setUp(void) {}
void tearDown(void) {}

static meshtastic_FirmwareEdition persistedEdition()
{
    meshtastic_DeviceState saved = meshtastic_DeviceState_init_zero;
    TEST_ASSERT_EQUAL(LoadFileResult::LOAD_SUCCESS, nodeDB->loadProto(deviceStateFileName, meshtastic_DeviceState_size,
                                                                      sizeof(saved), &meshtastic_DeviceState_msg, &saved));
    return saved.my_node.firmware_edition;
}

static void test_boot_overwritesPersistedEventEditionWithBuildEdition(void)
{
    devicestate.my_node.firmware_edition = meshtastic_FirmwareEdition_DEFCON;
    TEST_ASSERT_TRUE(nodeDB->saveToDisk(SEGMENT_DEVICESTATE));
    TEST_ASSERT_EQUAL(meshtastic_FirmwareEdition_DEFCON, persistedEdition());

    NodeDB *rebooted = new NodeDB();
    delete nodeDB;
    nodeDB = rebooted;

    TEST_ASSERT_EQUAL(expectedEdition, devicestate.my_node.firmware_edition);
    // On disk too, not just in RAM: the stamp must land before the boot save decision.
    TEST_ASSERT_EQUAL(expectedEdition, persistedEdition());
}

FE_TEST_ENTRY void setup()
{
    initializeTestEnvironment();
    nodeDB = new NodeDB();

    UNITY_BEGIN();
    RUN_TEST(test_boot_overwritesPersistedEventEditionWithBuildEdition);
    exit(UNITY_END());
}
FE_TEST_ENTRY void loop() {}
