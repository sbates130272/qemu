/*
 * QEMU PCI MMIO Bridge - PCI Device Implementation
 *
 * Exposes the generic PCI MMIO Bridge as a standard PCI device.
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
#include "qemu/memalign.h"
#include "trace.h"

/* Memory region operations for BAR0 (shadow buffer) */
static void pci_mmio_bridge_bar_write(void *opaque, hwaddr addr,
                                      uint64_t value, unsigned size)
{
    PCIMMIOBridgePCIState *s = opaque;
    
    /* Delegate to core bridge shadow write handler */
    if (s->bridge && s->bridge->shadow_hva) {
        memcpy(s->bridge->shadow_hva + addr, &value, size);
        
        /* Trigger immediate poll if writing to producer index */
        if (addr < 4 && s->bridge->enabled && s->bridge->poll_bh) {
            qemu_bh_schedule(s->bridge->poll_bh);
        }
    }
}

static uint64_t pci_mmio_bridge_bar_read(void *opaque, hwaddr addr,
                                         unsigned size)
{
    PCIMMIOBridgePCIState *s = opaque;
    uint64_t value = 0;
    
    if (s->bridge && s->bridge->shadow_hva) {
        memcpy(&value, s->bridge->shadow_hva + addr, size);
    }
    
    return value;
}

static const MemoryRegionOps pci_mmio_bridge_bar_ops = {
    .read = pci_mmio_bridge_bar_read,
    .write = pci_mmio_bridge_bar_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

static void pci_mmio_bridge_pci_realize(PCIDevice *pci_dev, Error **errp)
{
    PCIMMIOBridgePCIState *s = PCI_MMIO_BRIDGE_PCI(pci_dev);
    uint8_t *pci_conf = pci_dev->config;
    struct pci_mmio_ring_meta *meta;

    /* Set PCI config space */
    pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_REDHAT_QEMU);
    pci_config_set_device_id(pci_conf, PCI_DEVICE_ID_MMIO_BRIDGE);
    pci_config_set_class(pci_conf, PCI_CLASS_SYSTEM_OTHER);
    pci_config_set_revision(pci_conf, 0x01);

    /* Subsystem vendor/device ID */
    pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID,
                 PCI_VENDOR_ID_REDHAT_QEMU);
    pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0x1100);

    /* Validate bar_size */
    if (s->bar_size < 4096) {
        error_setg(errp, "bar-size must be at least 4096 bytes");
        return;
    }

    /* Allocate core bridge state */
    s->bridge = g_new0(PCIMMIOBridgeState, 1);
    
    /* Store PCI bus reference */
    s->bridge->pci_bus = pci_get_bus(pci_dev);
    
    /* Allocate shadow buffer backing memory */
    s->bridge->shadow_hva = qemu_memalign(4096, s->bar_size);
    memset(s->bridge->shadow_hva, 0, s->bar_size);
    s->bridge->shadow_size = s->bar_size;
    
    /* Initialize BAR0 with custom ops */
    memory_region_init_io(&s->bar, OBJECT(s), &pci_mmio_bridge_bar_ops,
                          s, "pci-mmio-bridge-bar0", s->bar_size);
    
    /* Register BAR0 as a 32-bit memory BAR */
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &s->bar);

    /* Calculate queue depth */
    s->bridge->queue_depth = 
        (s->bar_size / sizeof(struct pci_mmio_command)) - 1;

    /* Initialize ring buffer metadata in shadow buffer */
    meta = (struct pci_mmio_ring_meta *)s->bridge->shadow_hva;
    meta->producer_idx = 0;
    meta->consumer_idx = 0;
    meta->queue_depth = s->bridge->queue_depth;
    meta->reserved = 0;

    /* Initialize polling infrastructure */
    s->bridge->poll_interval_ns = s->poll_interval_ns ? 
                                   s->poll_interval_ns : 1000000;
    
    s->bridge->poll_bh = qemu_bh_new(pci_mmio_bridge_poll, s->bridge);
    s->bridge->poll_timer = timer_new_ns(QEMU_CLOCK_REALTIME,
                                         pci_mmio_bridge_poll, s->bridge);
    s->bridge->enabled = s->enabled;

    /* Start polling if enabled */
    if (s->enabled) {
        timer_mod(s->bridge->poll_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + 
                  s->bridge->poll_interval_ns);
    }

    /* Get BAR address for tracing */
    PCIIORegion *region = &pci_dev->io_regions[0];
    s->bridge->shadow_gpa = region->addr != PCI_BAR_UNMAPPED ?
                            region->addr : 0;

    trace_pci_mmio_bridge_pci_realize(s->bar_size, s->bridge->queue_depth);
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

    /* Stop polling */
    if (s->bridge->poll_timer) {
        timer_free(s->bridge->poll_timer);
        s->bridge->poll_timer = NULL;
    }
    if (s->bridge->poll_bh) {
        qemu_bh_delete(s->bridge->poll_bh);
        s->bridge->poll_bh = NULL;
    }

    /* Free shadow buffer */
    if (s->bridge->shadow_hva) {
        qemu_vfree(s->bridge->shadow_hva);
        s->bridge->shadow_hva = NULL;
    }

    g_free(s->bridge);
    s->bridge = NULL;
}

static void pci_mmio_bridge_pci_reset(Object *obj, ResetType type)
{
    PCIMMIOBridgePCIState *s = PCI_MMIO_BRIDGE_PCI(obj);
    struct pci_mmio_ring_meta *meta;

    if (!s->bridge || !s->bridge->shadow_hva) {
        return;
    }

    /* Reset ring buffer state */
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
    DEFINE_PROP_UINT32("bar-size", PCIMMIOBridgePCIState, bar_size, 4096),
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

