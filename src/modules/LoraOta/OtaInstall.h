#pragma once
// Installs a verified staged image over the application. Runs from a static constructor, before the
// SoftDevice and FreeRTOS start, and executes from RAM while it rewrites the application flash.

#include <stddef.h>
#include <stdint.h>

namespace lora_ota
{

constexpr uint8_t INSTALL_MAGIC = 0xC5; // GPREGRET: not one of the OTAFIX bootloader's values, so it survives the reset
constexpr uint32_t BL_SETTINGS_ADDR = 0xFF000;

// Arms the install for the next boot; the caller then reboots.
void requestInstall();

// Checks GPREGRET and, if armed and the staged image is Ready, installs it and resets (never returns then).
void installIfRequested();

// Hardware access, provided by the firmware (OtaInstall.cpp) or by the host emulator.
namespace hw
{
uint8_t gpregretGet();
void gpregretSet(uint8_t v);
void nvmcErase(uint32_t pageAddr);
void nvmcWrite(uint32_t addr, const uint32_t *words, size_t count);
void watchdogFeed();
void irqDisable();
[[noreturn]] void systemReset();
} // namespace hw

} // namespace lora_ota
