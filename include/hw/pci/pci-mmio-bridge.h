/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU PCI MMIO Bridge
 *
 * Copyright (c) 2025 Stephen Bates <sbates@raithlin.com>
 */

#ifndef HW_PCI_MMIO_BRIDGE_H
#define HW_PCI_MMIO_BRIDGE_H

#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "qom/object.h"

/*
 * MMIO Bridge Command Packet Structure
 *
 */
struct pci_mmio_bridge_command {
    uint16_t target_bdf;      /* Bus:Device:Function (bus|devfn) */
    uint8_t  target_bar;      /* Which BAR on target device (0-5) */
    uint8_t  reserved1;
    uint32_t offset;          /* Offset within BAR */

    uint64_t value;           /* Value to write, or returned value for read */

    uint8_t  command;         /* Command type (see CMD_* below) */
    uint8_t  size;            /* Transfer size: 1, 2, 4, or 8 bytes */
    uint8_t  status;          /* Status (see STATUS_* below) */
    uint8_t  reserved2;
    uint32_t sequence;        /* Sequence number for ordering */
} QEMU_PACKED;

/* Command types */
#define PCI_MMIO_BRIDGE_CMD_NOP    0
#define PCI_MMIO_BRIDGE_CMD_WRITE  1
#define PCI_MMIO_BRIDGE_CMD_READ   2

/* Status codes */
#define PCI_MMIO_BRIDGE_STATUS_PENDING   0
#define PCI_MMIO_BRIDGE_STATUS_COMPLETE  1
#define PCI_MMIO_BRIDGE_STATUS_ERROR     2

/* Ring buffer metadata (stored in first command slot) */
struct pci_mmio_bridge_ring_meta {
    uint32_t producer_idx;    /* Guest/device write index (tail) */
    uint32_t consumer_idx;    /* QEMU read index (head) */
    uint32_t queue_depth;     /* Total number of command slots */
    uint32_t reserved;
} QEMU_PACKED;

/*
 * PCI MMIO Bridge State
 *
 */
typedef struct PCIMMIOBridge {
    /* Shadow buffer (guest RAM for DMA access) */
    MemoryRegion shadow_mr;
    hwaddr shadow_gpa;        /* Guest physical address */
    void *shadow_hva;         /* Host virtual address for polling */
    uint32_t shadow_size;     /* Size in bytes */

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
} PCIMMIOBridge;

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
PCIMMIOBridge *pci_mmio_bridge_init(struct PCIBus *pci_bus,
                                         hwaddr gpa, uint32_t size,
                                         uint64_t poll_interval_ns,
                                         Error **errp);

/*
 * Cleanup the PCI MMIO bridge
 */
void pci_mmio_bridge_cleanup(PCIMMIOBridge *bridge);

/*
 * Enable/disable the bridge
 */
void pci_mmio_bridge_set_enabled(PCIMMIOBridge *bridge, bool enabled);

/*
 * Get bridge statistics (for QMP/monitor)
 */
void pci_mmio_bridge_get_stats(PCIMMIOBridge *bridge,
                               uint64_t *total_commands,
                               uint64_t *total_writes,
                               uint64_t *total_reads,
                               uint64_t *total_errors);

/*
 * Manually trigger one poll cycle (for testing)
 *
 * This is useful in qtest environments where timers don't automatically fire.
 */
void pci_mmio_bridge_poll_once(PCIMMIOBridge *bridge);

/*
 * Internal polling callback
 */
void pci_mmio_bridge_poll(void *opaque);


/*
 * PCI Device Interface
 */

/*
 * Vendor-specific capability offsets in PCI config space
 * These expose the shadow buffer GPA and size to guest drivers
 */
#define PCI_MMIO_BRIDGE_CAP_OFFSET  0x40
#define PCI_MMIO_BRIDGE_CAP_GPA_LO  0x00  /* Lower 32 bits of GPA */
#define PCI_MMIO_BRIDGE_CAP_GPA_HI  0x04  /* Upper 32 bits of GPA */
#define PCI_MMIO_BRIDGE_CAP_SIZE    0x08  /* Buffer size */
#define PCI_MMIO_BRIDGE_CAP_DEPTH   0x0C  /* Queue depth */

#define TYPE_PCI_MMIO_BRIDGE "pci-mmio-bridge"
OBJECT_DECLARE_SIMPLE_TYPE(PCIMMIOBridge_NEW, PCI_MMIO_BRIDGE)

struct PCIMMIOBridge_NEW {
    PCIDevice parent_obj;

    /* Core bridge state */
    PCIMMIOBridge *bridge;

    /* Configuration properties */
    uint64_t shadow_gpa;       /* Guest physical address (0 = auto) */
    uint32_t shadow_size;      /* Size of shadow buffer */
    uint64_t poll_interval_ns; /* Polling interval */
    bool enabled;              /* Whether bridge is active */
};
#endif /* HW_PCI_MMIO_BRIDGE_H */
