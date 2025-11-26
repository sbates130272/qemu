/*
 * QEMU PCI BAR Mirror Infrastructure
 *
 * Copyright (c) 2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This header defines a generic, reusable PCI BAR mirror infrastructure
 * that allows any PCIe device to expose a RAM-backed "mirror" BAR that
 * transparently forwards all accesses to another MMIO BAR.
 *
 * Key features:
 * - Device-agnostic: Works with any PCIDevice
 * - Opt-in: Zero overhead when disabled
 * - Efficient: Uses dirty memory tracking for DMA detection
 * - Composable: Mix-in pattern like other PCI capabilities
 *
 * Usage pattern:
 *   1. Add PCIMirrorState field to device state
 *   2. Include DEFINE_PCI_MIRROR_PROPERTIES in device properties
 *   3. Call pci_mirror_init() in device realize()
 *   4. Call pci_mirror_cleanup() in device exit()
 */

#ifndef HW_PCI_MIRROR_H
#define HW_PCI_MIRROR_H

#include "hw/pci/pci.h"
#include "qemu/timer.h"

/**
 * PCIMirrorState - PCI BAR mirror state
 *
 * This structure can be embedded in any PCIDevice-derived structure
 * to provide BAR mirroring capability.
 *
 * Configuration fields (set before pci_mirror_init):
 * @enabled: Enable mirror feature (default: false)
 * @mirror_bar_num: Mirror BAR number 0-5 (default: 3)
 * @target_bar_num: Target BAR number 0-5 (default: 0)
 * @mirror_size: Size of mirror BAR, must be power of 2 (default: 0)
 * @target_offset: Offset within target BAR (default: 0)
 * @sync_reads: Synchronize reads from target BAR (default: false)
 * @poll_interval_ns: Polling interval in nanoseconds (default: 10000)
 *
 * Private fields (managed by infrastructure):
 * @pci_dev: Parent PCI device
 * @target_mr: Target BAR MemoryRegion
 * @mirror_mr: Mirror BAR MemoryRegion
 * @ram: RAM backing storage
 * @poll_timer: Polling timer for DMA detection
 *
 * Statistics fields (read-only):
 * @cpu_read_count: Number of CPU reads from mirror BAR
 * @cpu_write_count: Number of CPU writes to mirror BAR
 * @dma_write_count: Number of detected DMA writes
 * @forward_count: Total number of forwards to target BAR
 * @error_count: Number of errors encountered
 *
 * Example:
 *   typedef struct MyDeviceState {
 *       PCIDevice parent_obj;
 *       MemoryRegion bar0;
 *       PCIMirrorState mirror;  // Add this field
 *   } MyDeviceState;
 */
typedef struct PCIMirrorState {
    /* Configuration (set by device before init) */
    bool enabled;
    uint8_t mirror_bar_num;
    uint8_t target_bar_num;
    uint64_t mirror_size;
    uint64_t target_offset;
    bool sync_reads;
    uint64_t poll_interval_ns;

    /* Private state (managed by infrastructure) */
    PCIDevice *pci_dev;
    MemoryRegion *target_mr;
    MemoryRegion mirror_mr;
    void *ram;
    QEMUTimer *poll_timer;

    /* Statistics (read-only) */
    uint64_t cpu_read_count;
    uint64_t cpu_write_count;
    uint64_t dma_write_count;
    uint64_t forward_count;
    uint64_t error_count;
} PCIMirrorState;

/**
 * pci_mirror_init - Initialize PCI BAR mirror
 * @pci_dev: Parent PCI device
 * @mirror: Mirror state structure (must be pre-configured)
 * @target_mr: Target BAR MemoryRegion to mirror
 * @errp: Error pointer
 *
 * This function validates the configuration, allocates resources,
 * initializes the mirror BAR, enables dirty memory tracking, and
 * starts the polling timer.
 *
 * The mirror BAR will be registered with the PCI core using
 * pci_register_bar() with appropriate flags (64-bit, prefetchable).
 *
 * Returns: 0 on success, -1 on error (with errp set)
 */
int pci_mirror_init(PCIDevice *pci_dev,
                    PCIMirrorState *mirror,
                    MemoryRegion *target_mr,
                    Error **errp);

/**
 * pci_mirror_cleanup - Clean up PCI BAR mirror
 * @mirror: Mirror state structure
 *
 * Stops the polling timer, disables dirty tracking, frees resources.
 * Safe to call multiple times or if mirror is disabled.
 */
void pci_mirror_cleanup(PCIMirrorState *mirror);

/**
 * pci_mirror_reset - Reset mirror statistics
 * @mirror: Mirror state structure
 *
 * Called during device reset to clear counters.
 * Safe to call if mirror is disabled.
 */
void pci_mirror_reset(PCIMirrorState *mirror);

/**
 * DEFINE_PCI_MIRROR_PROPERTIES - Define standard mirror properties
 * @_type: Device type name
 * @_field: Name of PCIMirrorState field in device structure
 *
 * Macro to define standard mirror properties that devices can include
 * in their property arrays.
 *
 * Properties defined:
 * - mirror-enabled (bool): Enable mirror feature
 * - mirror-bar-num (uint8): Mirror BAR number (0-5)
 * - mirror-target-bar (uint8): Target BAR number (0-5)
 * - mirror-size (size): Size of mirror BAR
 * - mirror-target-offset (uint64): Offset in target BAR
 * - mirror-sync-reads (bool): Sync reads from target
 * - mirror-poll-interval (uint64): Poll interval in nanoseconds
 *
 * Example:
 *   static Property mydev_properties[] = {
 *       DEFINE_PROP_STRING("serial", MyDevice, serial),
 *       DEFINE_PCI_MIRROR_PROPERTIES(MyDevice, mirror),
 *       DEFINE_PROP_END_OF_LIST
 *   };
 */
#define DEFINE_PCI_MIRROR_PROPERTIES(_type, _field) \
    DEFINE_PROP_BOOL("mirror-enabled", _type, _field.enabled, false), \
    DEFINE_PROP_UINT8("mirror-bar-num", _type, \
                      _field.mirror_bar_num, 3), \
    DEFINE_PROP_UINT8("mirror-target-bar", _type, \
                      _field.target_bar_num, 0), \
    DEFINE_PROP_SIZE("mirror-size", _type, _field.mirror_size, 0), \
    DEFINE_PROP_UINT64("mirror-target-offset", _type, \
                       _field.target_offset, 0), \
    DEFINE_PROP_BOOL("mirror-sync-reads", _type, \
                     _field.sync_reads, false), \
    DEFINE_PROP_UINT64("mirror-poll-interval", _type, \
                       _field.poll_interval_ns, 10000)

#endif /* HW_PCI_MIRROR_H */

