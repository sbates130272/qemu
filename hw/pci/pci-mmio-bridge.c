/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QEMU PCI MMIO Bridge Implementation
 *
 * Provides PCI device-to-device MMIO capability via a command queue.
 *
 * Copyright (c) 2025 Stephen Bates <sbates@raithlin.com>
 */

#include "qemu/osdep.h"
#include "qemu/memalign.h"
#include "qemu/main-loop.h"
#include "hw/pci/pci-mmio-bridge.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pci_bus.h"
#include "system/address-spaces.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "trace.h"
#include "hw/core/qdev-properties.h"
#include "hw/core/resettable.h"
#include "qemu/module.h"
#include "exec/target_page.h"

/* Default polling interval: 1ms */
#define DEFAULT_POLL_INTERVAL_NS (1000 * 1000)

/* Helper: Extract bus number from BDF */
static inline uint8_t bdf_to_bus(uint16_t bdf)
{
    return (bdf >> 8) & 0xFF;
}

/* Helper: Extract devfn from BDF */
static inline uint8_t bdf_to_devfn(uint16_t bdf)
{
    return bdf & 0xFF;
}

/*
 * Find PCI device by BDF
 *
 * Searches the configured PCI bus for a device matching the given BDF.
 * Returns NULL if not found.
 */
static PCIDevice *pci_mmio_bridge_find_device(PCIMMIOBridge *bridge,
                                              uint16_t bdf)
{
    uint8_t bus_num = bdf_to_bus(bdf);
    uint8_t devfn = bdf_to_devfn(bdf);
    PCIDevice *dev;

    if (!bridge->pci_bus) {
        return NULL;
    }

    dev = pci_find_device(bridge->pci_bus, bus_num, devfn);
    if (!dev) {
        trace_pci_mmio_bridge_device_not_found(bdf);
    }

    return dev;
}

/*
 * Execute a single MMIO command
 *
 * Dispatches the command to the appropriate target device's MMIO handler.
 */
static void pci_mmio_bridge_execute_command(
    PCIMMIOBridge *bridge, struct pci_mmio_bridge_command *cmd)
{
    PCIDevice *target;
    uint64_t value = 0;
    MemTxResult result;

    /* Validate command type */
    switch (cmd->command) {
    case PCI_MMIO_BRIDGE_CMD_WRITE:
    case PCI_MMIO_BRIDGE_CMD_READ:
        break;
    default:
        qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
        smp_wmb();  /* Ensure status visible before return */
        trace_pci_mmio_bridge_invalid_command(cmd->command);
        return;
    }

    /* Find target device */
    target = pci_mmio_bridge_find_device(bridge, cmd->target_bdf);
    if (!target) {
        qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
        smp_wmb();  /* Ensure status is visible to guest */
        trace_pci_mmio_bridge_device_not_found(cmd->target_bdf);
        return;
    }

    /* Validate BAR number */
    if (cmd->target_bar >= PCI_NUM_REGIONS) {
        qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
        smp_wmb();  /* Ensure status visible before return */
        trace_pci_mmio_bridge_invalid_bar(cmd->target_bdf, cmd->target_bar);
        return;
    }

    /* Get target BAR address */
    hwaddr bar_addr = pci_get_bar_addr(target, cmd->target_bar);
    if (bar_addr == PCI_BAR_UNMAPPED) {
        qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
        smp_wmb();  /* Ensure status visible to guest */
        trace_pci_mmio_bridge_bar_not_mapped(cmd->target_bdf, cmd->target_bar);
        return;
    }

    /* Validate size */
    if (cmd->size != 1 && cmd->size != 2 && cmd->size != 4 && cmd->size != 8) {
        qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
        smp_wmb();  /* Ensure status visible to guest */
        trace_pci_mmio_bridge_invalid_size(cmd->size);
        return;
    }

    /* Calculate full MMIO address (BAR base + offset) */
    hwaddr mmio_addr = bar_addr + cmd->offset;

    /* Execute the operation using address_space to access MMIO space */
    switch (cmd->command) {
    case PCI_MMIO_BRIDGE_CMD_WRITE:
        result = address_space_write(&address_space_memory, mmio_addr,
                                      MEMTXATTRS_UNSPECIFIED,
                                      &cmd->value, cmd->size);
        if (result == MEMTX_OK) {
            qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_COMPLETE);
            smp_wmb();  /* Ensure status visible to guest */
            bridge->total_writes++;
            trace_pci_mmio_bridge_write(cmd->target_bdf, cmd->target_bar,
                                        cmd->offset, cmd->value, cmd->size);
        } else {
            qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
            smp_wmb();  /* Ensure status visible to guest */
            bridge->total_errors++;
            trace_pci_mmio_bridge_write_failed(cmd->target_bdf, cmd->target_bar,
                                               cmd->offset, result);
        }
        break;

    case PCI_MMIO_BRIDGE_CMD_READ:
        result = address_space_read(&address_space_memory, mmio_addr,
                                     MEMTXATTRS_UNSPECIFIED,
                                     &value, cmd->size);
        if (result == MEMTX_OK) {
            cmd->value = value;
            smp_wmb();  /* Ensure value is visible before status update */
            qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_COMPLETE);
            smp_wmb();  /* Ensure status visible to guest */
            bridge->total_reads++;
            trace_pci_mmio_bridge_read(cmd->target_bdf, cmd->target_bar,
                                       cmd->offset, value, cmd->size);
        } else {
            qatomic_set(&cmd->status, PCI_MMIO_BRIDGE_STATUS_ERROR);
            smp_wmb();  /* Ensure status visible to guest */
            bridge->total_errors++;
            trace_pci_mmio_bridge_read_failed(cmd->target_bdf, cmd->target_bar,
                                              cmd->offset, result);
        }
        break;
    }

    /* Ensure status is visible */
    smp_wmb();
}

/*
 * Polling timer callback
 *
 * Checks shadow buffer for new commands and processes them.
 * This is exported for use by the PCI device wrapper.
 */
void pci_mmio_bridge_poll(void *opaque)
{
    PCIMMIOBridge *bridge = opaque;
    uint32_t producer_idx, consumer_idx;
    uint32_t commands_processed = 0;

    if (!bridge->enabled) {
        goto reschedule;
    }

    bridge->total_polls++;

    /*
     * Read metadata from guest memory using address_space_read. This ensures
     * we see any VFIO device writes and not cached copies.
     */
    struct pci_mmio_bridge_ring_meta metadata;
    address_space_read(&address_space_memory, bridge->shadow_gpa,
                       MEMTXATTRS_UNSPECIFIED, &metadata, sizeof(metadata));

    producer_idx = metadata.producer_idx;
    consumer_idx = bridge->head;

    /* Process all pending commands */
    while (consumer_idx != producer_idx) {
        uint32_t slot = consumer_idx % bridge->queue_depth;
        hwaddr cmd_addr = bridge->shadow_gpa +
                          sizeof(struct pci_mmio_bridge_ring_meta) +
                          (slot * sizeof(struct pci_mmio_bridge_command));

        /* Read command from guest memory to see GPU writes */
        struct pci_mmio_bridge_command cmd;
        address_space_read(&address_space_memory, cmd_addr,
                           MEMTXATTRS_UNSPECIFIED, &cmd, sizeof(cmd));

        if (cmd.status == PCI_MMIO_BRIDGE_STATUS_PENDING) {
            pci_mmio_bridge_execute_command(bridge, &cmd);

            /* Write back status using address_space_write */
            address_space_write(&address_space_memory, cmd_addr,
                                MEMTXATTRS_UNSPECIFIED, &cmd, sizeof(cmd));

            bridge->total_commands++;
            commands_processed++;
        }

        consumer_idx++;
    }

    /* Update our head position */
    bridge->head = consumer_idx;

    if (commands_processed > 0) {
        trace_pci_mmio_bridge_poll_processed(commands_processed);
    }

reschedule:
    /* Reschedule for next poll cycle */
    if (bridge->poll_timer) {
        timer_mod(bridge->poll_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  bridge->poll_interval_ns);
    }
}

/*
 * Initialize PCI MMIO Bridge
 */
PCIMMIOBridge *pci_mmio_bridge_init(PCIBus *pci_bus,
                                         hwaddr gpa, uint32_t size,
                                         uint64_t poll_interval_ns,
                                         Error **errp)
{
    PCIMMIOBridge *bridge;
    struct pci_mmio_bridge_ring_meta *meta;

    /* Validate parameters */
    if (!pci_bus) {
        error_setg(errp, "PCI bus must be provided");
        return NULL;
    }

    if (size < TARGET_PAGE_SIZE) {
        error_setg(errp, "Shadow buffer size must be at least 4096 bytes");
        return NULL;
    }

    if (!QEMU_IS_ALIGNED(gpa, TARGET_PAGE_SIZE)) {
        error_setg(errp, "Shadow buffer GPA must be page-aligned");
        return NULL;
    }

    /* Allocate bridge state */
    bridge = g_new0(PCIMMIOBridge, 1);

    /* Store PCI bus reference */
    bridge->pci_bus = pci_bus;

    bridge->shadow_gpa = gpa;
    bridge->shadow_size = size;

    /* Allocate guest RAM for shadow buffer with unique name */
    char *mr_name = g_strdup_printf("pci-mmio-bridge-shadow@0x%"PRIx64, gpa);
    memory_region_init_ram(&bridge->shadow_mr, NULL, mr_name, size,
                           &error_fatal);
    g_free(mr_name);

    /* Add to system memory at specified GPA */
    memory_region_add_subregion(get_system_memory(), gpa, &bridge->shadow_mr);

    /* Get host virtual address for direct access */
    bridge->shadow_hva = memory_region_get_ram_ptr(&bridge->shadow_mr);
    memset(bridge->shadow_hva, 0, size);

    /* Calculate queue depth (reserve first slot for metadata) */
    bridge->queue_depth = (size / sizeof(struct pci_mmio_bridge_command)) - 1;

    /* Initialize ring buffer metadata in first slot */
    meta = (struct pci_mmio_bridge_ring_meta *)bridge->shadow_hva;
    meta->producer_idx = 0;
    meta->consumer_idx = 0;
    meta->queue_depth = bridge->queue_depth;
    meta->reserved = 0;

    /* Initialize polling infrastructure */
    bridge->poll_interval_ns = poll_interval_ns ? poll_interval_ns :
                                                   DEFAULT_POLL_INTERVAL_NS;

    /* Use bottom-half for immediate processing (for qtest) */
    bridge->poll_bh = qemu_bh_new(pci_mmio_bridge_poll, bridge);

    /* Also create timer for periodic polling when BH isn't triggered */
    bridge->poll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                      pci_mmio_bridge_poll, bridge);
    bridge->enabled = true;

    /* Start periodic polling */
    timer_mod(bridge->poll_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              bridge->poll_interval_ns);

    trace_pci_mmio_bridge_init(gpa, size, bridge->queue_depth,
                               bridge->poll_interval_ns);

    return bridge;
}

/*
 * Cleanup PCI MMIO Bridge
 */
void pci_mmio_bridge_cleanup(PCIMMIOBridge *bridge)
{
    if (!bridge) {
        return;
    }

    trace_pci_mmio_bridge_cleanup(bridge->total_commands, bridge->total_writes,
                                  bridge->total_reads, bridge->total_errors);

    /* Stop polling */
    if (bridge->poll_timer) {
        timer_free(bridge->poll_timer);
    }
    if (bridge->poll_bh) {
        qemu_bh_delete(bridge->poll_bh);
    }

    /* Remove from system memory and cleanup */
    memory_region_del_subregion(get_system_memory(), &bridge->shadow_mr);
    object_unparent(OBJECT(&bridge->shadow_mr));

    /* Free backing memory */
    qemu_vfree(bridge->shadow_hva);

    g_free(bridge);
}

/*
 * Enable/disable bridge
 */
void pci_mmio_bridge_set_enabled(PCIMMIOBridge *bridge, bool enabled)
{
    if (bridge) {
        bridge->enabled = enabled;
        trace_pci_mmio_bridge_set_enabled(enabled);
    }
}

/*
 * Get statistics
 */
void pci_mmio_bridge_get_stats(PCIMMIOBridge *bridge,
                               uint64_t *total_commands,
                               uint64_t *total_writes,
                               uint64_t *total_reads,
                               uint64_t *total_errors)
{
    if (bridge) {
        if (total_commands) {
            *total_commands = bridge->total_commands;
        }
        if (total_writes) {
            *total_writes = bridge->total_writes;
        }
        if (total_reads) {
            *total_reads = bridge->total_reads;
        }
        if (total_errors) {
            *total_errors = bridge->total_errors;
        }
    }
}

/*
 * Manually trigger one poll cycle
 *
 * This is primarily for testing - it processes pending commands immediately
 * without waiting for the timer.
 */
void pci_mmio_bridge_poll_once(PCIMMIOBridge *bridge)
{
    if (bridge) {
        pci_mmio_bridge_poll(bridge);
    }
}

/*
 * PCI Device Wrapper
 */

static void pci_mmio_bridge_pci_realize(PCIDevice *pci_dev, Error **errp)
{
    PCIMMIOBridge_NEW *s = PCI_MMIO_BRIDGE(pci_dev);
    uint8_t *pci_conf = pci_dev->config;
    Error *local_err = NULL;

    /* Set PCI config space */
    pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_REDHAT);
    pci_config_set_device_id(pci_conf, PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE);
    pci_config_set_class(pci_conf, PCI_CLASS_SYSTEM_OTHER);
    pci_config_set_revision(pci_conf, 0x01);

    /* Subsystem vendor/device ID */
    pci_set_word(pci_conf + PCI_SUBSYSTEM_VENDOR_ID,
                 PCI_VENDOR_ID_REDHAT);
    pci_set_word(pci_conf + PCI_SUBSYSTEM_ID, 0x1100);

    /* Validate shadow_size */
    if (s->shadow_size < TARGET_PAGE_SIZE) {
        error_setg(errp, "shadow-size must be at least %d bytes",
            TARGET_PAGE_SIZE);
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

    trace_pci_mmio_bridge_realize(s->shadow_gpa, s->shadow_size,
                                      s->bridge->queue_depth);
}

static void pci_mmio_bridge_pci_exit(PCIDevice *pci_dev)
{
    PCIMMIOBridge_NEW *s = PCI_MMIO_BRIDGE(pci_dev);

    if (!s->bridge) {
        return;
    }

    trace_pci_mmio_bridge_exit(s->bridge->total_commands,
                                   s->bridge->total_writes,
                                   s->bridge->total_reads,
                                   s->bridge->total_errors);

    /* Use bridge cleanup (handles guest RAM removal) */
    pci_mmio_bridge_cleanup(s->bridge);
    s->bridge = NULL;
}

static void pci_mmio_bridge_pci_reset(Object *obj, ResetType type)
{
    PCIMMIOBridge_NEW *s = PCI_MMIO_BRIDGE(obj);
    struct pci_mmio_bridge_ring_meta *meta;

    if (!s->bridge || !s->bridge->shadow_hva) {
        return;
    }

    /* Reset ring buffer state in guest RAM */
    meta = (struct pci_mmio_bridge_ring_meta *)s->bridge->shadow_hva;
    meta->producer_idx = 0;
    meta->consumer_idx = 0;
    s->bridge->head = 0;

    /* Reset statistics */
    s->bridge->total_commands = 0;
    s->bridge->total_writes = 0;
    s->bridge->total_reads = 0;
    s->bridge->total_errors = 0;
    s->bridge->total_polls = 0;

    trace_pci_mmio_bridge_reset();
}

static const Property pci_mmio_bridge_pci_properties[] = {
    DEFINE_PROP_UINT64("shadow-gpa", PCIMMIOBridge_NEW, shadow_gpa, 0),
    DEFINE_PROP_UINT32("shadow-size", PCIMMIOBridge_NEW, shadow_size,
                       4096),
    DEFINE_PROP_UINT64("poll-interval-ns", PCIMMIOBridge_NEW,
                       poll_interval_ns, 1000000),
    DEFINE_PROP_BOOL("enabled", PCIMMIOBridge_NEW, enabled, true)
};

static void pci_mmio_bridge_pci_class_init(ObjectClass *klass,
                                            const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    ResettableClass *rc = RESETTABLE_CLASS(klass);

    k->realize = pci_mmio_bridge_pci_realize;
    k->exit = pci_mmio_bridge_pci_exit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE;
    k->class_id = PCI_CLASS_SYSTEM_OTHER;
    k->revision = 0x01;

    dc->desc = "PCI MMIO Bridge (device-to-device MMIO proxy)";
    rc->phases.hold = pci_mmio_bridge_pci_reset;
    device_class_set_props(dc, pci_mmio_bridge_pci_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo pci_mmio_bridge_pci_info = {
    .name          = TYPE_PCI_MMIO_BRIDGE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCIMMIOBridge_NEW),
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

