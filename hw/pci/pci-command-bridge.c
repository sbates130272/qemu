/*
 * QEMU PCI Command Bridge Infrastructure
 *
 * Copyright (c) 2024 Stephen Bates <sbates@raithlin.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "hw/pci/pci_command_bridge.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "qemu/atomic.h"
#include "qemu/timer.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "trace.h"

/*
 * Polling timer callback
 *
 * This function is called periodically to check for new commands
 * written by VFIO devices via DMA to the RAM-backed command BAR.
 */
static void pci_command_bridge_poll_timer_cb(void *opaque)
{
    PCICommandBridgeState *bridge = opaque;
    PCIDevice *pci_dev = bridge->pci_dev;
    PCICommandRegion *cmd_region;
    uint32_t current_magic, current_seq, last_seq;
    uint32_t cmd_magic;
    uint16_t cmd_status;
    uint8_t cmd_bar, cmd_size;
    uint64_t cmd_offset, cmd_data;
    uint64_t completion_addr, completion_magic;
    MemoryRegion *target_mr = NULL;
    MemTxResult result;
    const char *dev_name = object_get_canonical_path_component(
        OBJECT(pci_dev));

    if (!bridge->enabled || !bridge->cmd_ram) {
        goto reschedule;
    }

    /* Get pointer to RAM backing the command BAR */
    cmd_region = (PCICommandRegion *)bridge->cmd_ram;

    /* Read current synchronization values */
    current_magic = qatomic_read(&cmd_region->magic);
    current_seq = qatomic_read(&cmd_region->sequence);
    last_seq = qatomic_read(&cmd_region->last_sequence);

    /*
     * Basic polling: detect any DMA write
     * Check for valid magic and changed sequence number
     */
    if (current_magic == PCI_CMD_BRIDGE_MAGIC_VALUE &&
        current_seq != last_seq) {
        uint32_t poll_count = qatomic_read(&cmd_region->poll_count);

        /* Update poll count and last sequence */
        qatomic_set(&cmd_region->poll_count, poll_count + 1);
        qatomic_set(&cmd_region->last_sequence, current_seq);

        trace_pci_command_bridge_dma_write_detected(dev_name,
                                                     current_seq,
                                                     poll_count + 1);
    }

    /*
     * Command execution: check for valid command and execute it
     */
    cmd_magic = qatomic_read(&cmd_region->cmd_magic);
    if (cmd_magic != PCI_CMD_BRIDGE_CMD_MAGIC) {
        goto reschedule;
    }

    /* Check if this is a new command (sequence changed) */
    if (current_seq == bridge->last_cmd_seq) {
        goto reschedule;
    }

    cmd_status = qatomic_read(&cmd_region->cmd_status);
    if (cmd_status != PCI_CMD_BRIDGE_STATUS_PENDING) {
        goto reschedule;
    }

    /* Read command parameters */
    uint32_t cmd_opcode = qatomic_read(&cmd_region->cmd_opcode);
    cmd_bar = qatomic_read(&cmd_region->cmd_bar);
    cmd_size = qatomic_read(&cmd_region->cmd_size);
    cmd_offset = qatomic_read(&cmd_region->cmd_offset);
    cmd_data = qatomic_read(&cmd_region->cmd_data);
    uint64_t cmd_read_addr = qatomic_read(&cmd_region->cmd_read_addr);
    completion_addr = qatomic_read(&cmd_region->cmd_completion_addr);
    completion_magic = qatomic_read(&cmd_region->cmd_completion_magic);

    trace_pci_command_bridge_execute_start(dev_name, cmd_bar, cmd_offset,
                                            cmd_size, cmd_data);

    /* Resolve target BAR using callback */
    if (bridge->get_bar) {
        target_mr = bridge->get_bar(pci_dev, cmd_bar);
    }

    if (!target_mr) {
        qatomic_set(&cmd_region->cmd_status, PCI_CMD_BRIDGE_STATUS_ERROR);
        qatomic_set(&cmd_region->cmd_error_code,
                   PCI_CMD_BRIDGE_ERROR_BAR_INVALID);
        trace_pci_command_bridge_error(dev_name, "Invalid BAR",
                                        PCI_CMD_BRIDGE_ERROR_BAR_INVALID);
        goto reschedule;
    }

    /* Validate size */
    if (cmd_size != 1 && cmd_size != 2 && cmd_size != 4 && cmd_size != 8) {
        qatomic_set(&cmd_region->cmd_status, PCI_CMD_BRIDGE_STATUS_ERROR);
        qatomic_set(&cmd_region->cmd_error_code,
                   PCI_CMD_BRIDGE_ERROR_SIZE_INVALID);
        trace_pci_command_bridge_error(dev_name, "Invalid size",
                                        PCI_CMD_BRIDGE_ERROR_SIZE_INVALID);
        goto reschedule;
    }

    /*
     * Execute MMIO operation based on opcode
     */
    if (cmd_opcode == PCI_CMD_BRIDGE_OP_WRITE) {
        /* MMIO write - triggers target BAR's write callback */
        result = memory_region_dispatch_write(target_mr, cmd_offset, cmd_data,
                                             size_memop(cmd_size) | MO_LE,
                                             MEMTXATTRS_UNSPECIFIED);
    } else if (cmd_opcode == PCI_CMD_BRIDGE_OP_READ) {
        /* MMIO read - triggers target BAR's read callback */
        uint64_t read_value = 0;
        result = memory_region_dispatch_read(target_mr, cmd_offset,
                                            &read_value,
                                            size_memop(cmd_size) | MO_LE,
                                            MEMTXATTRS_UNSPECIFIED);
        
        if (result == MEMTX_OK) {
            /* Store result in cmd_data field */
            qatomic_set(&cmd_region->cmd_data, read_value);
            
            /* Optionally write result to guest-specified GPA */
            if (cmd_read_addr != 0) {
                AddressSpace *as = pci_get_address_space(pci_dev);
                address_space_write(as, cmd_read_addr,
                                  MEMTXATTRS_UNSPECIFIED,
                                  &read_value, cmd_size);
                trace_pci_command_bridge_read_result(dev_name, cmd_read_addr,
                                                      read_value);
            }
        }
    } else {
        /* Invalid opcode */
        qatomic_set(&cmd_region->cmd_status, PCI_CMD_BRIDGE_STATUS_ERROR);
        qatomic_set(&cmd_region->cmd_error_code,
                   PCI_CMD_BRIDGE_ERROR_INVALID_OP);
        trace_pci_command_bridge_error(dev_name, "Invalid opcode",
                                        PCI_CMD_BRIDGE_ERROR_INVALID_OP);
        goto reschedule;
    }

    /* Update command status */
    if (result == MEMTX_OK) {
        uint32_t exec_count = qatomic_read(&cmd_region->cmd_exec_count);

        qatomic_set(&cmd_region->cmd_status, PCI_CMD_BRIDGE_STATUS_SUCCESS);
        qatomic_set(&cmd_region->cmd_error_code,
                   PCI_CMD_BRIDGE_ERROR_NONE);
        qatomic_set(&cmd_region->cmd_exec_count, exec_count + 1);

        trace_pci_command_bridge_execute_success(dev_name, cmd_bar,
                                                  cmd_offset, exec_count + 1);

        /* Write completion magic to guest memory if requested */
        if (completion_addr != 0) {
            AddressSpace *as = pci_get_address_space(pci_dev);
            address_space_write(as, completion_addr, MEMTXATTRS_UNSPECIFIED,
                               &completion_magic, sizeof(completion_magic));
            trace_pci_command_bridge_completion(dev_name, completion_addr,
                                                 completion_magic);
        }
    } else {
        qatomic_set(&cmd_region->cmd_status, PCI_CMD_BRIDGE_STATUS_ERROR);
        qatomic_set(&cmd_region->cmd_error_code,
                   PCI_CMD_BRIDGE_ERROR_OUT_OF_RANGE);
        trace_pci_command_bridge_error(dev_name, "MMIO dispatch failed",
                                        PCI_CMD_BRIDGE_ERROR_OUT_OF_RANGE);
    }

    bridge->last_cmd_seq = current_seq;

reschedule:
    /* Re-arm timer for next poll */
    if (bridge->poll_timer && bridge->poll_interval_ns > 0) {
        timer_mod(bridge->poll_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  bridge->poll_interval_ns);
    }
}

/*
 * Initialize command bridge infrastructure
 */
int pci_command_bridge_init(PCIDevice *pci_dev,
                             PCICommandBridgeState *bridge,
                             MemoryRegion *(*get_bar)(PCIDevice *, uint8_t),
                             Error **errp)
{
    const char *dev_name = object_get_canonical_path_component(
        OBJECT(pci_dev));

    if (!bridge->enabled) {
        return 0;
    }

    /* Validate configuration */
    if (bridge->cmd_bar_size < PCI_CMD_BRIDGE_MIN_SIZE) {
        error_setg(errp, "cmd-bridge-size must be at least %d bytes",
                   PCI_CMD_BRIDGE_MIN_SIZE);
        return -1;
    }

    if (bridge->poll_interval_ns < 1000) {
        error_setg(errp, "cmd-bridge-poll-interval must be at least 1000ns");
        return -1;
    }

    if (bridge->cmd_bar_num > 5) {
        error_setg(errp, "cmd-bridge-bar must be 0-5");
        return -1;
    }

    /* Store references */
    bridge->pci_dev = pci_dev;
    bridge->get_bar = get_bar;

    /* Allocate RAM for command BAR */
    bridge->cmd_ram = g_malloc0(bridge->cmd_bar_size);

    /* Initialize the RAM-backed memory region */
    memory_region_init_ram_ptr(&bridge->cmd_mr, OBJECT(pci_dev),
                               "pci-command-bridge-bar",
                               bridge->cmd_bar_size,
                               bridge->cmd_ram);

    /* Register the command BAR */
    pci_register_bar(pci_dev, bridge->cmd_bar_num,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64 |
                     PCI_BASE_ADDRESS_MEM_PREFETCH,
                     &bridge->cmd_mr);

    /* Initialize polling timer */
    bridge->poll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                      pci_command_bridge_poll_timer_cb,
                                      bridge);

    /* Start polling */
    if (bridge->poll_interval_ns > 0) {
        timer_mod(bridge->poll_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                  bridge->poll_interval_ns);
    }

    trace_pci_command_bridge_init(dev_name, bridge->cmd_bar_num,
                                   bridge->cmd_bar_size,
                                   bridge->poll_interval_ns);

    return 0;
}

/*
 * Clean up command bridge resources
 */
void pci_command_bridge_cleanup(PCICommandBridgeState *bridge)
{
    const char *dev_name = object_get_canonical_path_component(
        OBJECT(bridge->pci_dev));

    if (!bridge->enabled) {
        return;
    }

    trace_pci_command_bridge_cleanup(dev_name);

    /* Stop and free timer */
    if (bridge->poll_timer) {
        timer_free(bridge->poll_timer);
        bridge->poll_timer = NULL;
    }

    /* Free RAM backing */
    if (bridge->cmd_ram) {
        g_free(bridge->cmd_ram);
        bridge->cmd_ram = NULL;
    }
}

/*
 * Reset command bridge state
 */
void pci_command_bridge_reset(PCICommandBridgeState *bridge)
{
    const char *dev_name;

    if (!bridge->enabled || !bridge->cmd_ram) {
        return;
    }

    dev_name = object_get_canonical_path_component(OBJECT(bridge->pci_dev));

    trace_pci_command_bridge_reset(dev_name);

    /* Clear command region */
    memset(bridge->cmd_ram, 0, bridge->cmd_bar_size);

    /* Reset internal state */
    bridge->last_cmd_seq = 0;
}

