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

#ifndef HW_PCI_COMMAND_BRIDGE_H
#define HW_PCI_COMMAND_BRIDGE_H

#include "hw/pci/pci_device.h"
#include "qemu/timer.h"

/*
 * PCI Command Bridge - Generic infrastructure for RAM-backed BARs
 * that allow VFIO devices to issue commands to emulated device BARs
 *
 * This provides a generic mechanism where:
 * 1. A RAM-backed BAR contains a command structure
 * 2. VFIO devices can DMA write commands to this BAR
 * 3. QEMU polls the BAR and executes commands as MMIO operations
 * 4. Commands trigger callbacks on target BARs (MMIO or I/O)
 */

/* Command protocol constants */
#define PCI_CMD_BRIDGE_MAGIC_VALUE     0xDEADBEEF
#define PCI_CMD_BRIDGE_CMD_MAGIC       0xDEADC0DE
#define PCI_CMD_BRIDGE_MIN_SIZE        0x1000  /* 4KB minimum */

/* Command opcodes */
#define PCI_CMD_BRIDGE_OP_WRITE  0
#define PCI_CMD_BRIDGE_OP_READ   1

/* Command status codes */
#define PCI_CMD_BRIDGE_STATUS_PENDING  0
#define PCI_CMD_BRIDGE_STATUS_SUCCESS  1
#define PCI_CMD_BRIDGE_STATUS_ERROR    2

/* Error codes */
#define PCI_CMD_BRIDGE_ERROR_NONE         0
#define PCI_CMD_BRIDGE_ERROR_BAR_INVALID  1
#define PCI_CMD_BRIDGE_ERROR_SIZE_INVALID 2
#define PCI_CMD_BRIDGE_ERROR_OUT_OF_RANGE 3
#define PCI_CMD_BRIDGE_ERROR_INVALID_OP   4

/*
 * Command Region Layout (in RAM-backed BAR)
 *
 * This structure is mapped in the RAM-backed BAR and accessed by
 * both the VFIO device (via DMA) and QEMU (via polling).
 */
typedef struct PCICommandRegion {
    /* Basic synchronization header */
    volatile uint32_t magic;         /* 0x00: Magic for validity */
    volatile uint32_t sequence;      /* 0x04: Sequence from DMA writer */
    volatile uint32_t poll_count;    /* 0x08: Poll detection count */
    volatile uint32_t last_sequence; /* 0x0C: Last seq QEMU saw */

    /* Command structure for MMIO operations */
    volatile uint32_t cmd_magic;     /* 0x10: Command magic value */
    volatile uint32_t cmd_opcode;    /* 0x14: Operation (WRITE/READ) */
    volatile uint8_t  cmd_bar;       /* 0x18: Target BAR number */
    volatile uint8_t  cmd_size;      /* 0x19: Operation size (1,2,4,8) */
    volatile uint16_t cmd_status;    /* 0x1A: Command status */
    volatile uint64_t cmd_offset;    /* 0x1C: Offset in target BAR */
    volatile uint64_t cmd_data;      /* 0x24: Write data OR read result */
    volatile uint32_t cmd_exec_count;/* 0x2C: Number of commands executed */
    volatile uint32_t cmd_error_code;/* 0x30: Error code if failed */
    volatile uint64_t cmd_read_addr; /* 0x34: GPA for read result (optional) */
    volatile uint64_t cmd_completion_addr; /* 0x3C: GPA for completion */
    volatile uint64_t cmd_completion_magic;/* 0x44: Magic to write on completion */

    uint8_t padding[0xB4];           /* 0x4C-0xFF: Reserved */
    uint8_t data[0xF00];             /* 0x100+: Additional data area */
} PCICommandRegion;

/*
 * PCI Command Bridge State
 *
 * This structure should be embedded in a PCIDevice's state structure.
 * It manages the command bridge BAR and polling infrastructure.
 */
typedef struct PCICommandBridgeState {
    PCIDevice *pci_dev;              /* Parent PCI device */
    bool enabled;                    /* Command bridge enabled */
    uint8_t cmd_bar_num;             /* BAR number for command region */
    uint64_t cmd_bar_size;           /* Size of command BAR */
    uint64_t poll_interval_ns;       /* Polling interval (nanoseconds) */

    MemoryRegion cmd_mr;             /* The RAM-backed command BAR */
    void *cmd_ram;                   /* Host memory backing */
    QEMUTimer *poll_timer;           /* Timer for polling */

    uint32_t last_cmd_seq;           /* Last command sequence executed */

    /* Callback to resolve BAR number to MemoryRegion */
    MemoryRegion *(*get_bar)(PCIDevice *pci_dev, uint8_t bar_num);
} PCICommandBridgeState;

/*
 * Property definitions macro
 *
 * Use this in your device's property array to add command bridge
 * configuration options.
 *
 * Example:
 *   static Property my_device_props[] = {
 *       ... other properties ...
 *       DEFINE_PCI_COMMAND_BRIDGE_PROPERTIES(MyDeviceState, cmd_bridge),
 *       DEFINE_PROP_END_OF_LIST
 *   };
 */
#define DEFINE_PCI_COMMAND_BRIDGE_PROPERTIES(_type, _field) \
    DEFINE_PROP_BOOL("cmd-bridge-enabled", _type, \
                     _field.enabled, false), \
    DEFINE_PROP_UINT8("cmd-bridge-bar", _type, \
                      _field.cmd_bar_num, 3), \
    DEFINE_PROP_SIZE("cmd-bridge-size", _type, \
                     _field.cmd_bar_size, 0), \
    DEFINE_PROP_UINT64("cmd-bridge-poll-interval", _type, \
                       _field.poll_interval_ns, 10000)

/*
 * Public API
 */

/**
 * pci_command_bridge_init - Initialize command bridge infrastructure
 * @pci_dev: Parent PCI device
 * @bridge: Command bridge state structure
 * @get_bar: Callback to resolve BAR numbers to MemoryRegions
 * @errp: Error pointer
 *
 * Call this in the device's realize function to set up the command
 * bridge BAR and polling infrastructure.
 *
 * Returns: 0 on success, -1 on failure
 */
int pci_command_bridge_init(PCIDevice *pci_dev,
                             PCICommandBridgeState *bridge,
                             MemoryRegion *(*get_bar)(PCIDevice *, uint8_t),
                             Error **errp);

/**
 * pci_command_bridge_cleanup - Clean up command bridge resources
 * @bridge: Command bridge state structure
 *
 * Call this in the device's unrealize/exit function.
 */
void pci_command_bridge_cleanup(PCICommandBridgeState *bridge);

/**
 * pci_command_bridge_reset - Reset command bridge state
 * @bridge: Command bridge state structure
 *
 * Call this in the device's reset function.
 */
void pci_command_bridge_reset(PCICommandBridgeState *bridge);

#endif /* HW_PCI_COMMAND_BRIDGE_H */

