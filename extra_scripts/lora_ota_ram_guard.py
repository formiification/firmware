#!/usr/bin/env python3
# trunk-ignore-all(ruff/F821)
# trunk-ignore-all(flake8/F821): For SConstruct imports
#
# Post-link guard for the LoRa OTA installer: it rewrites the application flash while running, so every
# function it reaches must live in RAM (.data) and must never branch back into flash.
import os
import re

Import("env")

_tc = env.PioPlatform().get_package_dir("toolchain-gccarmnoneeabi") or ""
_OBJDUMP = os.path.join(_tc, "bin", "arm-none-eabi-objdump")
if not os.path.isfile(_OBJDUMP):
    _OBJDUMP = "arm-none-eabi-objdump"
RAM = (0x20000000, 0x20040000)
APP = (0x26000, 0xE9000)  # application + staging, below the OTA meta page
REQUIRED = ("ramInstall", "ota_unxz_run", "xz_dec_lzma2_run", "nvmcErase", "nvmcWrite")


def _check(source, target, env):
    import subprocess
    import sys

    elf = env.subst("$BUILD_DIR/${PROGNAME}.elf")
    dis = subprocess.check_output([_OBJDUMP, "-d", "-j", ".data", elf], universal_newlines=True)
    fn, funcs, bad = None, [], []
    for line in dis.splitlines():
        m = re.match(r"^([0-9a-f]+) <(.+)>:$", line)
        if m:
            fn = m.group(2)
            funcs.append(fn)
            if "veneer" in fn:
                bad.append("%s (a veneer in RAM means RAM code calls a far function)" % fn)
            continue
        w = re.search(r"\.word\s+0x([0-9a-f]+)", line)
        if w and fn and APP[0] <= int(w.group(1), 16) < APP[1]:
            bad.append("%s: literal 0x%s points into the application flash being rewritten" % (fn, w.group(1)))
        m = re.match(r"^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+(bl|blx|b\.w|b|b\w\w(?:\.w)?)\s+([0-9a-f]+)", line)
        if m and fn:
            t = int(m.group(2), 16)
            if not RAM[0] <= t < RAM[1]:
                bad.append("%s: %s 0x%x" % (fn, m.group(1), t))
    missing = [r for r in REQUIRED if not any(r in f for f in funcs)]
    if bad or missing:
        sys.stderr.write("\n*** LoRa OTA RAM guard failed ***\n")
        for b in bad:
            sys.stderr.write("  branch out of RAM: %s\n" % b)
        for r in missing:
            sys.stderr.write("  not RAM-resident (inlined into flash code?): %s\n" % r)
        from SCons.Script import Exit

        Exit(1)
    print("lora_ota_ram_guard: OK -- %d RAM functions, no branches into flash" % len([f for f in funcs]))


if "MESHTASTIC_LORA_OTA" in str(env.get("CPPDEFINES", "")) or "MESHTASTIC_LORA_OTA" in env.subst("$BUILD_FLAGS"):
    env.AddPostAction("$BUILD_DIR/${PROGNAME}.elf", _check)
