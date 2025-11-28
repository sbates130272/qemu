/*
 * QEMU Generic PCI MMIO Bridge
 *
 * Provides a software-based mechanism for PCI devices to issue MMIO
 * operations to other PCI devices via DMA-accessible command packets.
 *
 * Copyright (c) 2024 Your Name
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_PCI_MMIO_BRIDGE_H
#define HW_PCI_MMIO_BRIDGE_H

#include "hw/pci/pci.h"

/*
 * Command packet structure in shadow buffer
 *
 * Layout is carefully designed for atomic operations and alignment:
 * - 24 bytes total (fits in single cache line on most architectures)
 * - Command and status fields support lock-free ring buffer
 * - Value field can hold up to 64-bit data
 */
struct pci_mmio_command {
    /* Target device identification (8 bytes) */
    uint16_t target_bdf;      /* Bus:Device:Function (bits 15:8 bus, 7:0 devfn) */
    uint8_t  target_bar;      /* Which BAR on target device (0-5) */
    uint8_t  reserved1;
    uint32_t offset;          /* Offset within BAR */

    /* Operation details (8 bytes) */
    uint64_t value;           /* Value to write, or returned value for read */

    /* Command control (8 bytes) */
    uint8_t  command;         /* Command type (see CMD_* below) */
    uint8_t  size;            /* Transfer size: 1, 2, 4, or 8 bytes */
    uint8_t  status;          /* Status (see STATUS_* below) */
    uint8_t  reserved2;
    uint32_t sequence;        /* Sequence number for ordering */
} QEMU_PACKED;

/* Command types */
#define PCI_MMIO_CMD_NOP    0
#define PCI_MMIO_CMD_WRITE  1
#define PCI_MMIO_CMD_READ   2

/* Status codes */
#define PCI_MMIO_STATUS_PENDING   0
#define PCI_MMIO_STATUS_COMPLETE  1
#define PCI_MMIO_STATUS_ERROR     2

/* Ring buffer metadata (stored in first command slot) */
struct pci_mmio_ring_meta {
    uint32_t producer_idx;    /* Guest/device write index (tail) */
    uint32_t consumer_idx;    /* QEMU read index (head) */
    uint32_t queue_depth;     /* Total number of command slots */
    uint32_t reserved;
} QEMU_PACKED;

/*
 * PCI MMIO Bridge State
 *
 * This is a machine-level component, not a PCI device itself.
 * It's instantiated by the machine and provides service to all devices.
 */
typedef struct PCIMMIOBridgeState {
    /* Shadow buffer (guest RAM for DMA access) */
    MemoryRegion shadow_mr;
    hwaddr shadow_gpa;        /* Guest physical address */
    void *shadow_hva;         /* Host virtual address for polling */
    uint32_t shadow_size;     /* Size in bytes (typically 4096) */

    /* PCI bus to search for devices */
    struct PCIBus *pci_bus;   /* Main PCI bus */

    /* Ring buffer management */
    uint32_t queue_depth;     /* Number of command slots available */
    uint32_t head;            /* Consumer index (QEMU's position) */

    /* Polling infrastructure */
    QEMUTimer *poll_timer;
    QEMUBH *poll_bh;
    uint64_t poll_interval_ns;
    bool enabled;
    bool use_bh;              /* Use BH instead of timer (for qtest) */

    /* Statistics for monitoring/debugging */
    uint64_t total_commands;
    uint64_t total_writes;
    uint64_t total_reads;
    uint64_t total_errors;
    uint64_t total_polls;
} PCIMMIOBridgeState;

/*
 * Initialize the PCI MMIO bridge
 *
 * @pci_bus: PCI bus to monitor for devices
 * @gpa: Guest physical address for shadow buffer (must be page-aligned)
 * @size: Size of shadow buffer in bytes (must be >= 4096)
 * @poll_interval_ns: Polling interval in nanoseconds (0 = default)
 * @errp: Error pointer
 *
 * Returns: Pointer to bridge state on success, NULL on error
 */
PCIMMIOBridgeState *pci_mmio_bridge_init(struct PCIBus *pci_bus,
                                         hwaddr gpa, uint32_t size,
                                         uint64_t poll_interval_ns,
                                         Error **errp);

/*
 * Cleanup the PCI MMIO bridge
 */
void pci_mmio_bridge_cleanup(PCIMMIOBridgeState *bridge);

/*
 * Enable/disable the bridge
 */
void pci_mmio_bridge_set_enabled(PCIMMIOBridgeState *bridge, bool enabled);

/*
 * Get bridge statistics (for QMP/monitor)
 */
void pci_mmio_bridge_get_stats(PCIMMIOBridgeState *bridge,
                               uint64_t *total_commands,
                               uint64_t *total_writes,
                               uint64_t *total_reads,
                               uint64_t *total_errors);

/*
 * Manually trigger one poll cycle (for testing)
 *
 * This is useful in qtest environments where timers don't automatically fire.
 */
void pci_mmio_bridge_poll_once(PCIMMIOBridgeState *bridge);

#endif /* HW_PCI_MMIO_BRIDGE_H */

