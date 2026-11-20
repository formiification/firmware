#!/usr/bin/env python3
# trunk-ignore-all(ruff/F821)
# trunk-ignore-all(flake8/F821): For SConstruct imports
import json
import re
import sys
import shutil
from os import remove
from os.path import getmtime, isdir, isfile, join

Import("env")


# From https://github.com/platformio/platform-espressif32/blob/develop/builder/main.py
def _parse_size(value):
    if isinstance(value, int):
        return value
    elif value.isdigit():
        return int(value)
    elif value.startswith("0x"):
        return int(value, 16)
    elif value[-1].upper() in ("K", "M"):
        base = 1024 if value[-1].upper() == "K" else 1024 * 1024
        return int(value[:-1]) * base
    return value


def _parse_partitions(env):
    partitions_csv = env.subst("$PARTITIONS_TABLE_CSV")
    if not isfile(partitions_csv):
        sys.stderr.write(
            "Could not find the file %s with partitions " "table.\n" % partitions_csv
        )
        env.Exit(1)
        return

    result = []
    # The first offset is 0x9000 because partition table is flashed to 0x8000 and
    # occupies an entire flash sector, which size is 0x1000
    next_offset = 0x9000
    with open(partitions_csv) as fp:
        for line in fp.readlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tokens = [t.strip() for t in line.split(",")]
            if len(tokens) < 5:
                continue

            bound = 0x10000 if tokens[1] in ("0", "app") else 4
            calculated_offset = (next_offset + bound - 1) & ~(bound - 1)
            partition = {
                "name": tokens[0],
                "type": tokens[1],
                "subtype": tokens[2],
                "offset": tokens[3] or calculated_offset,
                "size": tokens[4],
                "flags": tokens[5] if len(tokens) > 5 else None,
            }
            result.append(partition)
            next_offset = _parse_size(partition["offset"]) + _parse_size(
                partition["size"]
            )

    return result


def mtjson_esp32_part(target, source, env):
    part = _parse_partitions(env)
    pj = json.dumps(part)
    # print(f"JSON_PARTITIONS: {pj}")
    # Dump json string to 'custom_mtjson_part' variable to use later when writing the manifest
    env.Replace(custom_mtjson_part=pj)


env.AddPreAction("mtjson", mtjson_esp32_part)


# ---------------------------------------------------------------------------
# HybridCompile cache-poisoning workaround (pioarduino platform-espressif32)
#
# The platform decides whether the precompiled Arduino IDF libs can be reused
# by hashing only the custom_sdkconfig text + mcu
# (builder/frameworks/arduino.py::matching_custom_sdkconfig). The board JSON's
# PSRAM configuration (BOARD_HAS_PSRAM / memory_type) is not part of that
# hash, and nearly all our S3 variants share esp32s3_base's identical
# custom_sdkconfig. Building a PSRAM env (e.g. heltec-v4) followed by a
# no-PSRAM env (e.g. heltec-v3) therefore skips the framework-libs recompile
# and links CONFIG_SPIRAM=y libs into the no-PSRAM firmware, which boot-loops
# with "quad_psram: PSRAM chip is not connected".
#
# Workaround: before the platform's arduino.py SConscript reads the option,
# append a comment line derived from the board's PSRAM/memory configuration to
# this env's custom_sdkconfig. The comment is inert in kconfig but changes the
# md5, forcing the IDF-libs recompile whenever the PSRAM class changes. The
# derivation mirrors espidf.py::generate_board_specific_config().
#
# The marker must stay lowercase: arduino.py greps custom_sdkconfig for the
# substrings "PSRAM" and "CONFIG_SPIRAM=y" (has_psram_config) and would
# otherwise treat every board as having PSRAM.
# ---------------------------------------------------------------------------

SDKCONFIG_CACHE_KEY = "meshtastic_hybridcompile_cache_key"


def spiram_cache_class(env):
    board = env.BoardConfig()
    mcu = board.get("build.mcu", "esp32")

    # memory_type: platformio.ini override > build.arduino.memory_type > build.memory_type
    memory_type = None
    try:
        memory_type = env.GetProjectOption("board_build.memory_type", None)
    except Exception:
        pass
    if not memory_type:
        build_section = board.get("build", {})
        memory_type = build_section.get("arduino", {}).get(
            "memory_type"
        ) or build_section.get("memory_type")

    extra_flags = board.get("build.extra_flags", "")
    if isinstance(extra_flags, str):
        has_psram = "PSRAM" in extra_flags
    else:
        has_psram = any("PSRAM" in str(flag) for flag in extra_flags)
    if not has_psram:
        if memory_type and (
            "opi" in memory_type.lower() or "psram" in memory_type.lower()
        ):
            has_psram = True
        elif "psram_type" in board.get("build", {}):
            has_psram = True

    if has_psram:
        psram_type = None
        try:
            psram_type = env.GetProjectOption("board_build.psram_type", None)
        except Exception:
            pass
        if not psram_type and memory_type and len(memory_type.split("_")) == 2:
            psram_type = memory_type.split("_")[1]
        if not psram_type:
            psram_type = board.get("build.psram_type", "") or (
                "hex" if mcu == "esp32p4" else "qio"
            )
        psram_type = psram_type.lower()
        if psram_type == "opi" and mcu == "esp32s3":
            spiram = "oct"
        elif psram_type == "hex":
            spiram = "hex"
        else:
            spiram = "quad"
    else:
        spiram = "none"

    return "memory_type=%s spiram=%s" % ((memory_type or "default").lower(), spiram)


def tag_sdkconfig_cache_key(env):
    config = env.GetProjectConfig()
    section = "env:" + env["PIOENV"]
    if not config.has_option(section, "custom_sdkconfig"):
        return
    current = env.GetProjectOption("custom_sdkconfig")
    if SDKCONFIG_CACHE_KEY in current:
        return
    marker = "# %s: %s" % (SDKCONFIG_CACHE_KEY, spiram_cache_class(env))
    cmake_args = env.BoardConfig().get("build.cmake_extra_args", "")
    if (
        cmake_args
    ):  # they and the .dummy/ hook below shape the IDF libs, so a change must rebuild them
        marker += " cmake=%s idfhook=1" % cmake_args
    config.set(section, "custom_sdkconfig", current.rstrip("\n") + "\n" + marker)


tag_sdkconfig_cache_key(env)


# The platform writes its cache-key hash into sdkconfig.defaults before compiling
# the IDF libs, so an aborted pass leaves it describing libs that were never built.
def drop_stale_sdkconfig_defaults(env):
    defaults = join(env.subst("$PROJECT_DIR"), "sdkconfig.defaults")
    board = env.BoardConfig()
    mcu = board.get("build.mcu", "esp32")
    # arduino.py's idf_lib_copy() writes the post-compile sdkconfig under
    # libs/<chip_variant>/, which only equals libs/<mcu>/ when the board has no
    # chip_variant override (e.g. esp32p4 boards use chip_variant "esp32p4_es").
    # Checking libs/<mcu>/ there would always see the untouched package template
    # and re-delete sdkconfig.defaults on every single build.
    chip_variant = board.get("build.chip_variant", "").lower() or mcu
    try:
        libs = env.PioPlatform().get_package_dir("framework-arduinoespressif32-libs")
        # Rewritten last by a completed compile, so it marks "libs built".
        if getmtime(join(libs, chip_variant, "sdkconfig")) >= getmtime(defaults):
            return
    except (OSError, TypeError):
        return
    print("*** Stale %s IDF libs; forcing a HybridCompile rebuild ***" % chip_variant)
    remove(defaults)


drop_stale_sdkconfig_defaults(env)


# ---------------------------------------------------------------------------
# Keep the HybridCompile pass out of the variant directory
#
# To build the IDF libs for custom_sdkconfig, espidf.py compiles a dummy sketch:
# it points PROJECT_SRC_DIR at .dummy/ and empties lib_deps and BUILD_FLAGS, but
# leaves SRC_FILTER alone. Entries that climb out of src/, such as
# +<../variants/esp32s3/t-deck-pro>, resolve the same from .dummy/, so the
# variant's .cpp files are compiled in that pass with no library include paths,
# and any of them that includes configuration.h fails on nanopb's pb.h.
#
# SRC_FILTER is substituted when the sources are collected, which is after
# espidf.py has set ARDUINO_LIB_COMPILE_FLAG=Build, so a callable can drop those
# entries for that pass alone and leave the real build untouched.
# ---------------------------------------------------------------------------


def scope_src_filter_in_lib_pass(env):
    src_filter = env.get("SRC_FILTER")
    if not src_filter:
        return
    if isinstance(src_filter, (list, tuple)):
        src_filter = " ".join(src_filter)
    patterns = re.findall(r"[+-]<[^>]*>", src_filter)
    within_src = [p for p in patterns if not p[2:].startswith("..")]
    if len(within_src) == len(patterns):
        return
    lib_pass_filter = " ".join(within_src)

    def project_src_filter(target, source, env, for_signature):
        if env.get("ARDUINO_LIB_COMPILE_FLAG") == "Build":
            return lib_pass_filter
        return src_filter

    env.Replace(
        MESHTASTIC_SRC_FILTER=project_src_filter, SRC_FILTER="${MESHTASTIC_SRC_FILTER}"
    )


scope_src_filter_in_lib_pass(env)


# board_build.cmake_extra_args can set MESHTASTIC_IDF_DEFINES, compile definitions for every IDF component
# in the libs build (e.g. lwIP options without a Kconfig). espidf.py drops CMAKE_C_FLAGS and builds the libs
# from the .dummy/ component it copies only when missing, so seed .dummy/ here and append the hook to it.
# The hook also fixes IDF 5.5's lwip_default_hooks.h, which declares lwip_dhcp_on_extra_option() without a
# prior `struct dhcp` and so fails to compile once the DHCP extra-option hook is enabled.
IDF_HOOK_MARKER = (
    "# meshtastic-idf-hook v1"  # bump together with idfhook= in the cache key
)
IDF_HOOK = IDF_HOOK_MARKER + """
if(MESHTASTIC_IDF_DEFINES)
    idf_build_set_property(COMPILE_DEFINITIONS "${MESHTASTIC_IDF_DEFINES}" APPEND)
endif()
if(CONFIG_LWIP_HOOK_DHCP_EXTRA_OPTION_CUSTOM OR CONFIG_LWIP_HOOK_DHCP_EXTRA_OPTION_DEFAULT)
    # lwip's target exists only once all components are added; EVAL bakes the values in now
    idf_component_get_property(meshtastic_lwip_lib lwip COMPONENT_LIB)
    cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY \\"${CMAKE_SOURCE_DIR}\\" CALL target_compile_options ${meshtastic_lwip_lib} PRIVATE \\"-include${CMAKE_CURRENT_LIST_DIR}/lwip_struct_dhcp.h\\")")
endif()
"""


def seed_dummy_component(env):
    if "MESHTASTIC_IDF_DEFINES" not in env.BoardConfig().get(
        "build.cmake_extra_args", ""
    ):
        return
    dummy = join(env.subst("$PROJECT_DIR"), ".dummy")
    if not isdir(dummy):
        template = join(env.PioPlatform().get_dir(), "builder", "build_lib")
        if not isdir(template):
            print(
                "Warning: %s missing, IDF libs build without the Meshtastic hook"
                % template
            )
            return
        shutil.copytree(template, dummy)
    with open(join(dummy, "lwip_struct_dhcp.h"), "w") as f:
        f.write("struct dhcp;\n")
    cmake = join(dummy, "CMakeLists.txt")
    with open(cmake) as f:
        content = f.read()
    if IDF_HOOK_MARKER not in content:
        content = content.split("\nif(MESHTASTIC_IDF_DEFINES)")[0].rstrip("\n") + "\n"
        with open(cmake, "w") as f:
            f.write(content + "\n" + IDF_HOOK)


seed_dummy_component(env)
