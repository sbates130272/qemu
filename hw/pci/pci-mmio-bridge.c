/*
 * QEMU Generic PCI MMIO Bridge Implementation
 *
 * Provides device-to-device MMIO capability via DMA-accessible command queue.
 *
 * Copyright (c) 2024 Your Name
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/cutils.h"
#include "qemu/memalign.h"
#include "qemu/main-loop.h"
#include "hw/pci/pci-mmio-bridge.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/pci/pci_bus.h"
#include "system/address-spaces.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "trace.h"

/* Default polling interval: 1ms */
#define DEFAULT_POLL_INTERVAL_NS (1000 * 1000)

/* Memory write callback - triggers immediate poll when producer index changes */
static void pci_mmio_bridge_shadow_write(void *opaque, hwaddr addr,
                                         uint64_t value, unsigned size)
{
    PCIMMIOBridgeState *bridge = opaque;
    
    /* Write through to actual RAM */
    memcpy(bridge->shadow_hva + addr, &value, size);
    
    /* If writing to producer index (first 4 bytes), trigger immediate poll */
    if (addr < 4 && bridge->enabled && bridge->poll_bh) {
        qemu_bh_schedule(bridge->poll_bh);
    }
}

static uint64_t pci_mmio_bridge_shadow_read(void *opaque, hwaddr addr,
                                             unsigned size)
{
    PCIMMIOBridgeState *bridge = opaque;
    uint64_t value = 0;
    
    memcpy(&value, bridge->shadow_hva + addr, size);
    return value;
}

static const MemoryRegionOps pci_mmio_bridge_shadow_ops = {
    .read = pci_mmio_bridge_shadow_read,
    .write = pci_mmio_bridge_shadow_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
    },
};

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
 * Currently only supports bus 0 (main PCI bus).
 * Returns NULL if not found.
 */
static PCIDevice *pci_mmio_bridge_find_device(PCIMMIOBridgeState *bridge,
                                              uint16_t bdf)
{
    uint8_t bus_num = bdf_to_bus(bdf);
    uint8_t devfn = bdf_to_devfn(bdf);
    PCIDevice *dev;

    if (!bridge->pci_bus) {
        return NULL;
    }

    /* For now, only support bus 0 (main PCI bus) */
    if (bus_num != 0) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "pci-mmio-bridge: Multi-bus not yet supported (BDF %04x)\n",
                      bdf);
        return NULL;
    }

    dev = bridge->pci_bus->devices[devfn];
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
static void pci_mmio_bridge_execute_command(PCIMMIOBridgeState *bridge,
                                             struct pci_mmio_command *cmd)
{
    PCIDevice *target;
    MemoryRegion *target_mr;
    uint64_t value;
    MemTxResult result;

    /* Validate command type */
    switch (cmd->command) {
    case PCI_MMIO_CMD_WRITE:
    case PCI_MMIO_CMD_READ:
        break;
    default:
        cmd->status = PCI_MMIO_STATUS_ERROR;
        trace_pci_mmio_bridge_invalid_command(cmd->command);
        return;
    }

    /* Find target device */
    target = pci_mmio_bridge_find_device(bridge, cmd->target_bdf);
    if (!target) {
        cmd->status = PCI_MMIO_STATUS_ERROR;
        trace_pci_mmio_bridge_device_not_found(cmd->target_bdf);
        return;
    }

    /* Validate BAR number */
    if (cmd->target_bar >= PCI_NUM_REGIONS) {
        cmd->status = PCI_MMIO_STATUS_ERROR;
        trace_pci_mmio_bridge_invalid_bar(cmd->target_bdf, cmd->target_bar);
        return;
    }

    /* Get target BAR memory region */
    target_mr = target->io_regions[cmd->target_bar].memory;
    if (!target_mr || !memory_region_is_mapped(target_mr)) {
        cmd->status = PCI_MMIO_STATUS_ERROR;
        trace_pci_mmio_bridge_bar_not_mapped(cmd->target_bdf, cmd->target_bar);
        return;
    }

    /* Validate size */
    if (cmd->size != 1 && cmd->size != 2 && cmd->size != 4 && cmd->size != 8) {
        cmd->status = PCI_MMIO_STATUS_ERROR;
        trace_pci_mmio_bridge_invalid_size(cmd->size);
        return;
    }

    /* Execute the operation */
    switch (cmd->command) {
    case PCI_MMIO_CMD_WRITE:
        result = memory_region_dispatch_write(target_mr, cmd->offset,
                                               cmd->value, size_memop(cmd->size),
                                               MEMTXATTRS_UNSPECIFIED);
        if (result == MEMTX_OK) {
            cmd->status = PCI_MMIO_STATUS_COMPLETE;
            bridge->total_writes++;
            trace_pci_mmio_bridge_write(cmd->target_bdf, cmd->target_bar,
                                        cmd->offset, cmd->value, cmd->size);
        } else {
            cmd->status = PCI_MMIO_STATUS_ERROR;
            bridge->total_errors++;
            trace_pci_mmio_bridge_write_failed(cmd->target_bdf, cmd->target_bar,
                                               cmd->offset, result);
        }
        break;

    case PCI_MMIO_CMD_READ:
        result = memory_region_dispatch_read(target_mr, cmd->offset,
                                              &value, size_memop(cmd->size),
                                              MEMTXATTRS_UNSPECIFIED);
        if (result == MEMTX_OK) {
            cmd->value = value;
            smp_wmb();  /* Ensure value is visible before status update */
            cmd->status = PCI_MMIO_STATUS_COMPLETE;
            bridge->total_reads++;
            trace_pci_mmio_bridge_read(cmd->target_bdf, cmd->target_bar,
                                       cmd->offset, value, cmd->size);
        } else {
            cmd->status = PCI_MMIO_STATUS_ERROR;
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
 */
static void pci_mmio_bridge_poll(void *opaque)
{
    PCIMMIOBridgeState *bridge = opaque;
    struct pci_mmio_ring_meta *meta;
    struct pci_mmio_command *queue;
    uint32_t producer_idx, consumer_idx;
    uint32_t commands_processed = 0;

    if (!bridge->enabled) {
        goto reschedule;
    }

    bridge->total_polls++;

    /* Get ring buffer metadata from first slot */
    meta = (struct pci_mmio_ring_meta *)bridge->shadow_hva;
    queue = (struct pci_mmio_command *)bridge->shadow_hva;

    /* Read producer index (written by guest/devices via DMA) */
    producer_idx = qatomic_read(&meta->producer_idx);
    consumer_idx = bridge->head;

    /* Process all pending commands */
    while (consumer_idx != producer_idx) {
        uint32_t slot = (consumer_idx % bridge->queue_depth) + 1;  /* +1 to skip metadata */
        struct pci_mmio_command *cmd = &queue[slot];

        /* Ensure command data is visible */
        smp_rmb();

        if (cmd->status == PCI_MMIO_STATUS_PENDING) {
            pci_mmio_bridge_execute_command(bridge, cmd);
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
                  qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + bridge->poll_interval_ns);
    }
}

/*
 * Initialize PCI MMIO Bridge
 */
PCIMMIOBridgeState *pci_mmio_bridge_init(PCIBus *pci_bus,
                                         hwaddr gpa, uint32_t size,
                                         uint64_t poll_interval_ns,
                                         Error **errp)
{
    PCIMMIOBridgeState *bridge;
    struct pci_mmio_ring_meta *meta;

    /* Validate parameters */
    if (!pci_bus) {
        error_setg(errp, "PCI bus must be provided");
        return NULL;
    }

    if (size < 4096) {
        error_setg(errp, "Shadow buffer size must be at least 4096 bytes");
        return NULL;
    }

    if (gpa & 0xFFF) {
        error_setg(errp, "Shadow buffer GPA must be page-aligned");
        return NULL;
    }

    /* Allocate bridge state */
    bridge = g_new0(PCIMMIOBridgeState, 1);

    /* Store PCI bus reference */
    bridge->pci_bus = pci_bus;

    /* Allocate backing memory */
    bridge->shadow_hva = qemu_memalign(4096, size);
    memset(bridge->shadow_hva, 0, size);
    bridge->shadow_gpa = gpa;
    bridge->shadow_size = size;

    /* Initialize shadow buffer as IO region with callbacks */
    memory_region_init_io(&bridge->shadow_mr, NULL,
                          &pci_mmio_bridge_shadow_ops, bridge,
                          "pci-mmio-bridge-shadow", size);

    /* Add to system memory */
    memory_region_add_subregion(get_system_memory(), gpa, &bridge->shadow_mr);

    /* Calculate queue depth (reserve first slot for metadata) */
    bridge->queue_depth = (size / sizeof(struct pci_mmio_command)) - 1;

    /* Initialize ring buffer metadata in first slot */
    meta = (struct pci_mmio_ring_meta *)bridge->shadow_hva;
    meta->producer_idx = 0;
    meta->consumer_idx = 0;
    meta->queue_depth = bridge->queue_depth;
    meta->reserved = 0;

    /* Initialize polling infrastructure */
    bridge->poll_interval_ns = poll_interval_ns ? poll_interval_ns :
                                                   DEFAULT_POLL_INTERVAL_NS;
    
    /* Use bottom-half for immediate processing (works in qtest) */
    bridge->poll_bh = qemu_bh_new(pci_mmio_bridge_poll, bridge);
    
    /* Also create timer for periodic polling when BH isn't triggered */
    bridge->poll_timer = timer_new_ns(QEMU_CLOCK_REALTIME,
                                      pci_mmio_bridge_poll, bridge);
    bridge->enabled = true;

    /* Start periodic polling */
    timer_mod(bridge->poll_timer,
              qemu_clock_get_ns(QEMU_CLOCK_REALTIME) + bridge->poll_interval_ns);

    trace_pci_mmio_bridge_init(gpa, size, bridge->queue_depth,
                               bridge->poll_interval_ns);

    return bridge;
}

/*
 * Cleanup PCI MMIO Bridge
 */
void pci_mmio_bridge_cleanup(PCIMMIOBridgeState *bridge)
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
void pci_mmio_bridge_set_enabled(PCIMMIOBridgeState *bridge, bool enabled)
{
    if (bridge) {
        bridge->enabled = enabled;
        trace_pci_mmio_bridge_set_enabled(enabled);
    }
}

/*
 * Get statistics
 */
void pci_mmio_bridge_get_stats(PCIMMIOBridgeState *bridge,
                               uint64_t *total_commands,
                               uint64_t *total_writes,
                               uint64_t *total_reads,
                               uint64_t *total_errors)
{
    if (bridge) {
        if (total_commands) *total_commands = bridge->total_commands;
        if (total_writes) *total_writes = bridge->total_writes;
        if (total_reads) *total_reads = bridge->total_reads;
        if (total_errors) *total_errors = bridge->total_errors;
    }
}

/*
 * Manually trigger one poll cycle
 *
 * This is primarily for testing - it processes pending commands immediately
 * without waiting for the timer.
 */
void pci_mmio_bridge_poll_once(PCIMMIOBridgeState *bridge)
{
    if (bridge) {
        pci_mmio_bridge_poll(bridge);
    }
}

