/*
 * QEMU PCI MMIO Bridge - PCI Device Implementation
 *
 * Exposes the generic PCI MMIO Bridge as a standard PCI device.
 *
 * IMPORTANT: This device allocates guest RAM (not PCI MMIO) for the shadow
 * buffer to enable VFIO DMA access. The GPA is exposed via vendor-specific
 * PCI config space registers.
 *
 * Copyright (c) 2024 Your Name
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "hw/pci/pci-mmio-bridge-pci.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "hw/resettable.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "trace.h"

/*
 * Vendor-specific capability offsets in PCI config space
 * These expose the shadow buffer GPA and size to guest drivers
 */
#define PCI_MMIO_BRIDGE_CAP_OFFSET  0x40
#define PCI_MMIO_BRIDGE_CAP_GPA_LO  0x00  /* Lower 32 bits of GPA */
#define PCI_MMIO_BRIDGE_CAP_GPA_HI  0x04  /* Upper 32 bits of GPA */
#define PCI_MMIO_BRIDGE_CAP_SIZE    0x08  /* Buffer size */
#define PCI_MMIO_BRIDGE_CAP_DEPTH   0x0C  /* Queue depth */

static void pci_mmio_bridge_pci_realize(PCIDevice *pci_dev, Error **errp)
{
    PCIMMIOBridgePCIState *s = PCI_MMIO_BRIDGE_PCI(pci_dev);
    uint8_t *pci_conf = pci_dev->config;
    Error *local_err = NULL;

    /* Set PCI config space */
    pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_REDHAT_QEMU);
    pci_config_set_device_id(pci_conf, PCI_DEVICE_ID_MMIO_BRIDGE);
    pci_config_set_class(pci_conf, PCI_CLASS_SYSTEM_OTHER);
    pci_config_set_revision(pci_conf, 0x01);

    /* Subsystem vendor/device ID */
    pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID,
                 PCI_VENDOR_ID_REDHAT_QEMU);
    pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0x1100);

    /* Validate shadow_size */
    if (s->shadow_size < 4096) {
        error_setg(errp, "shadow-size must be at least 4096 bytes");
        return;
    }

    /* Default GPA if not specified (below 4GB for 32-bit compatibility) */
    if (s->shadow_gpa == 0) {
        s->shadow_gpa = 0x80000000ULL;  /* Default: 2GB mark */
    }

    /* Use existing bridge initialization (creates guest RAM) */
    s->bridge = pci_mmio_bridge_init(pci_get_bus(pci_dev),
                                     s->shadow_gpa,
                                     s->shadow_size,
                                     s->poll_interval_ns,
                                     &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    s->bridge->enabled = s->enabled;

    /* Expose shadow buffer GPA and size via vendor-specific config space */
    pci_set_long(pci_conf + PCI_MMIO_BRIDGE_CAP_OFFSET + 
                 PCI_MMIO_BRIDGE_CAP_GPA_LO,
                 (uint32_t)(s->shadow_gpa & 0xFFFFFFFF));
    pci_set_long(pci_conf + PCI_MMIO_BRIDGE_CAP_OFFSET + 
                 PCI_MMIO_BRIDGE_CAP_GPA_HI,
                 (uint32_t)(s->shadow_gpa >> 32));
    pci_set_long(pci_conf + PCI_MMIO_BRIDGE_CAP_OFFSET + 
                 PCI_MMIO_BRIDGE_CAP_SIZE,
                 s->shadow_size);
    pci_set_long(pci_conf + PCI_MMIO_BRIDGE_CAP_OFFSET + 
                 PCI_MMIO_BRIDGE_CAP_DEPTH,
                 s->bridge->queue_depth);

    trace_pci_mmio_bridge_pci_realize(s->shadow_gpa, s->shadow_size,
                                      s->bridge->queue_depth);
}

static void pci_mmio_bridge_pci_exit(PCIDevice *pci_dev)
{
    PCIMMIOBridgePCIState *s = PCI_MMIO_BRIDGE_PCI(pci_dev);

    if (!s->bridge) {
        return;
    }

    trace_pci_mmio_bridge_pci_exit(s->bridge->total_commands,
                                   s->bridge->total_writes,
                                   s->bridge->total_reads,
                                   s->bridge->total_errors);

    /* Use bridge cleanup (handles guest RAM removal) */
    pci_mmio_bridge_cleanup(s->bridge);
    s->bridge = NULL;
}

static void pci_mmio_bridge_pci_reset(Object *obj, ResetType type)
{
    PCIMMIOBridgePCIState *s = PCI_MMIO_BRIDGE_PCI(obj);
    struct pci_mmio_ring_meta *meta;

    if (!s->bridge || !s->bridge->shadow_hva) {
        return;
    }

    /* Reset ring buffer state in guest RAM */
    meta = (struct pci_mmio_ring_meta *)s->bridge->shadow_hva;
    meta->producer_idx = 0;
    meta->consumer_idx = 0;
    s->bridge->head = 0;

    /* Reset statistics */
    s->bridge->total_commands = 0;
    s->bridge->total_writes = 0;
    s->bridge->total_reads = 0;
    s->bridge->total_errors = 0;
    s->bridge->total_polls = 0;

    trace_pci_mmio_bridge_pci_reset();
}

static const Property pci_mmio_bridge_pci_properties[] = {
    DEFINE_PROP_UINT64("shadow-gpa", PCIMMIOBridgePCIState, shadow_gpa, 0),
    DEFINE_PROP_UINT32("shadow-size", PCIMMIOBridgePCIState, shadow_size, 
                       4096),
    DEFINE_PROP_UINT64("poll-interval-ns", PCIMMIOBridgePCIState,
                       poll_interval_ns, 1000000),
    DEFINE_PROP_BOOL("enabled", PCIMMIOBridgePCIState, enabled, true)
};

static void pci_mmio_bridge_pci_class_init(ObjectClass *klass, 
                                            const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    k->realize = pci_mmio_bridge_pci_realize;
    k->exit = pci_mmio_bridge_pci_exit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT_QEMU;
    k->device_id = PCI_DEVICE_ID_MMIO_BRIDGE;
    k->class_id = PCI_CLASS_SYSTEM_OTHER;
    k->revision = 0x01;

    dc->desc = "PCI MMIO Bridge (device-to-device MMIO proxy)";
    rc->phases.hold = pci_mmio_bridge_pci_reset;
    device_class_set_props(dc, pci_mmio_bridge_pci_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo pci_mmio_bridge_pci_info = {
    .name          = TYPE_PCI_MMIO_BRIDGE_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIMMIOBridgePCIState),
    .class_init    = pci_mmio_bridge_pci_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { }
    }
};

static void pci_mmio_bridge_pci_register_types(void)
{
    type_register_static(&pci_mmio_bridge_pci_info);
}

type_init(pci_mmio_bridge_pci_register_types)

