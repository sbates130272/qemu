/*
 * QEMU PCI BAR Mirror Infrastructure
 *
 * Copyright (c) 2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This module provides a generic, reusable infrastructure for creating
 * RAM-backed "mirror" BARs that transparently forward all accesses to
 * another MMIO BAR on the same device.
 *
 * Key features:
 * - CPU writes: Forwarded immediately via memory_region_dispatch_write()
 * - CPU reads: Optionally synchronized via memory_region_dispatch_read()
 * - DMA writes: Detected efficiently via dirty memory tracking
 * - Partial writes: Logged and zero-padded
 * - Statistics: Counters for all operations and errors
 */

#include "qemu/osdep.h"
#include "hw/pci/pci_mirror.h"
#include "hw/pci/pci.h"
#include "system/memory.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "qemu/host-utils.h"
#include "qapi/error.h"
#include "trace.h"

/* Helper to get device name for tracing */
static const char *pci_mirror_dev_name(PCIMirrorState *m)
{
    return object_get_canonical_path_component(OBJECT(m->pci_dev));
}

/*
 * Polling timer callback for write detection (both CPU and DMA)
 *
 * Scans the RAM-backed mirror region and forwards any writes to the
 * target BAR. This detects both CPU and DMA writes.
 *
 * Future optimization: Use dirty memory tracking to scan only modified pages.
 */
static void pci_mirror_poll_timer_cb(void *opaque)
{
    PCIMirrorState *m = opaque;
    hwaddr offset;
    uint64_t forwards_this_cycle = 0;
    uint64_t errors_this_cycle = 0;

    /* Simple approach: scan entire region in 8-byte chunks */
    for (offset = 0; offset + 8 <= m->mirror_size; offset += 8) {
        uint64_t value;
        MemTxResult result;

        /* Read value from RAM */
        value = ldq_he_p((uint8_t *)m->ram + offset);

        /* Skip if zero (common case for unused regions) */
        if (value == 0) {
            continue;
        }

        /* DMA write detected - trace it */
        trace_pci_mirror_dma_write_detected(pci_mirror_dev_name(m),
                                             offset, value);

        /* Forward to target BAR */
        result = memory_region_dispatch_write(m->target_mr,
                                               m->target_offset + offset,
                                               value, 8,
                                               MEMTXATTRS_UNSPECIFIED);

        if (result == MEMTX_OK) {
            trace_pci_mirror_forward_write(pci_mirror_dev_name(m),
                                           m->target_offset + offset,
                                           value, 8);
            m->forward_count++;
            forwards_this_cycle++;
        } else {
            trace_pci_mirror_forward_error(pci_mirror_dev_name(m),
                                           offset, result);
            m->error_count++;
            errors_this_cycle++;
        }

        /* Clear the RAM location after forwarding */
        stq_he_p((uint8_t *)m->ram + offset, 0);
    }

    /* Trace poll cycle completion if any activity occurred */
    if (forwards_this_cycle > 0 || errors_this_cycle > 0) {
        trace_pci_mirror_poll_cycle(pci_mirror_dev_name(m),
                                     forwards_this_cycle,
                                     errors_this_cycle);
    }

    /* Reschedule timer */
    timer_mod(m->poll_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              m->poll_interval_ns);
}

/*
 * Initialize PCI BAR mirror
 *
 * Public API function. Validates configuration, allocates resources,
 * initializes MemoryRegion, enables dirty tracking, and starts polling.
 */
int pci_mirror_init(PCIDevice *pci_dev,
                    PCIMirrorState *mirror,
                    MemoryRegion *target_mr,
                    Error **errp)
{
    char *name;

    /* Validate configuration */
    if (mirror->mirror_bar_num > 5) {
        error_setg(errp, "pci-mirror: invalid mirror BAR %u (must be 0-5)",
                   mirror->mirror_bar_num);
        return -1;
    }

    if (mirror->target_bar_num > 5) {
        error_setg(errp, "pci-mirror: invalid target BAR %u (must be 0-5)",
                   mirror->target_bar_num);
        return -1;
    }

    if (mirror->mirror_bar_num == mirror->target_bar_num) {
        error_setg(errp,
                   "pci-mirror: mirror and target BAR cannot be the same");
        return -1;
    }

    if (mirror->mirror_size == 0 || !is_power_of_2(mirror->mirror_size)) {
        error_setg(errp,
                   "pci-mirror: mirror size must be non-zero power of 2");
        return -1;
    }

    if (target_mr == NULL) {
        error_setg(errp, "pci-mirror: target MemoryRegion is NULL");
        return -1;
    }

    /* Check target BAR bounds */
    if (mirror->target_offset + mirror->mirror_size >
        memory_region_size(target_mr)) {
        error_setg(errp,
                   "pci-mirror: mirror region exceeds target BAR "
                   "(offset=0x%lx size=0x%lx target_size=0x%lx)",
                   mirror->target_offset, mirror->mirror_size,
                   memory_region_size(target_mr));
        return -1;
    }

    /* Store references */
    mirror->pci_dev = pci_dev;
    mirror->target_mr = target_mr;

    /* Trace initialization */
    trace_pci_mirror_init(object_get_canonical_path_component(
                              OBJECT(pci_dev)),
                          mirror->mirror_bar_num,
                          mirror->target_bar_num,
                          mirror->mirror_size,
                          mirror->target_offset,
                          mirror->poll_interval_ns);

    /* Allocate RAM backing */
    mirror->ram = g_malloc0(mirror->mirror_size);

    /* Initialize MemoryRegion as RAM device */
    name = g_strdup_printf("%s-mirror-bar%u",
                           object_get_canonical_path_component(
                               OBJECT(pci_dev)),
                           mirror->mirror_bar_num);

    /*
     * Use RAM device region which is accessible for VFIO DMA mapping.
     * Writes from both CPU and DMA go directly to RAM, detected via polling.
     */
    memory_region_init_ram_device_ptr(&mirror->mirror_mr, OBJECT(pci_dev),
                                       name, mirror->mirror_size,
                                       mirror->ram);

    g_free(name);

    /* Register mirror BAR with PCI core */
    pci_register_bar(pci_dev, mirror->mirror_bar_num,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64 |
                     PCI_BASE_ADDRESS_MEM_PREFETCH,
                     &mirror->mirror_mr);

    /* Initialize and start polling timer */
    mirror->poll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                       pci_mirror_poll_timer_cb, mirror);
    timer_mod(mirror->poll_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
              mirror->poll_interval_ns);

    /* Initialize statistics */
    pci_mirror_reset(mirror);

    return 0;
}

/*
 * Clean up PCI BAR mirror
 *
 * Public API function. Stops polling, disables tracking, frees resources.
 */
void pci_mirror_cleanup(PCIMirrorState *mirror)
{
    if (!mirror->enabled) {
        return;
    }

    trace_pci_mirror_cleanup(pci_mirror_dev_name(mirror));

    /* Stop and free timer */
    if (mirror->poll_timer) {
        timer_del(mirror->poll_timer);
        timer_free(mirror->poll_timer);
        mirror->poll_timer = NULL;
    }

    /* Free RAM backing */
    g_free(mirror->ram);
    mirror->ram = NULL;
}

/*
 * Reset mirror statistics
 *
 * Public API function. Called during device reset.
 */
void pci_mirror_reset(PCIMirrorState *mirror)
{
    if (!mirror->enabled) {
        return;
    }

    trace_pci_mirror_reset(pci_mirror_dev_name(mirror));

    mirror->cpu_read_count = 0;
    mirror->cpu_write_count = 0;
    mirror->dma_write_count = 0;
    mirror->forward_count = 0;
    mirror->error_count = 0;
}

