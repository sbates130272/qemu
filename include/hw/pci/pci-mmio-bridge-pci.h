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

/* PCI IDs are defined in include/hw/pci/pci.h:
 * PCI_VENDOR_ID_REDHAT_QEMU = 0x1b36
 * PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE = 0x0015
 */

/*
 * PCI MMIO Bridge Device State
 *
 * This is the PCI device wrapper around the core bridge functionality.
 * Unlike a traditional PCI device, it allocates guest RAM (not MMIO)
 * for the shadow buffer to enable VFIO DMA access. The guest physical
 * address (GPA) is exposed via PCI config space vendor-specific registers.
 */
struct PCIMMIOBridgePCIState {
    PCIDevice parent_obj;

    /* Core bridge state */
    PCIMMIOBridgeState *bridge;

    /* Configuration properties */
    uint64_t shadow_gpa;       /* Guest physical address (0 = auto) */
    uint32_t shadow_size;      /* Size of shadow buffer */
    uint64_t poll_interval_ns; /* Polling interval */
    bool enabled;              /* Whether bridge is active */
};

#endif /* HW_PCI_MMIO_BRIDGE_PCI_H */

