/*
 * QEMU PCI MMIO Bridge - PCI Device Interface
 *
 * Provides a PCI device wrapper for the generic PCI MMIO Bridge,
 * making it discoverable via standard PCI mechanisms.
 *
 * Copyright (c) 2024 Your Name
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef HW_PCI_MMIO_BRIDGE_PCI_H
#define HW_PCI_MMIO_BRIDGE_PCI_H

#include "hw/pci/pci_device.h"
#include "hw/pci/pci-mmio-bridge.h"
#include "qom/object.h"

#define TYPE_PCI_MMIO_BRIDGE_PCI "pci-mmio-bridge"
OBJECT_DECLARE_SIMPLE_TYPE(PCIMMIOBridgePCIState, PCI_MMIO_BRIDGE_PCI)

/* PCI vendor/device IDs */
#define PCI_VENDOR_ID_REDHAT_QEMU  0x1b36
#define PCI_DEVICE_ID_MMIO_BRIDGE  0x0010

/*
 * PCI MMIO Bridge Device State
 *
 * This is the PCI device wrapper around the core bridge functionality.
 * It exposes the shadow buffer as BAR0, making it discoverable and
 * accessible via standard PCI mechanisms.
 */
struct PCIMMIOBridgePCIState {
    PCIDevice parent_obj;

    /* Core bridge state */
    PCIMMIOBridgeState *bridge;

    /* PCI BAR for shadow buffer */
    MemoryRegion bar;

    /* Configuration properties */
    uint32_t bar_size;        /* Size of BAR0 (shadow buffer) */
    uint64_t poll_interval_ns; /* Polling interval */
    bool enabled;             /* Whether bridge is active */
};

#endif /* HW_PCI_MMIO_BRIDGE_PCI_H */

