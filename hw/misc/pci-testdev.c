/*
 * QEMU PCI test device
 *
 * Copyright (c) 2012 Red Hat Inc.
 * Author: Michael S. Tsirkin <mst@redhat.com>
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
#include "hw/pci/pci_device.h"
#include "hw/qdev-properties.h"
#include "qemu/event_notifier.h"
#include "qemu/module.h"
#include "system/kvm.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "system/address-spaces.h"

typedef struct PCITestDevHdr {
    uint8_t test;
    uint8_t width;
    uint8_t pad0[2];
    uint32_t offset;
    uint8_t data;
    uint8_t pad1[3];
    uint32_t count;
    uint8_t name[];
} PCITestDevHdr;

typedef struct IOTest {
    MemoryRegion *mr;
    EventNotifier notifier;
    bool hasnotifier;
    unsigned size;
    bool match_data;
    PCITestDevHdr *hdr;
    unsigned bufsize;
} IOTest;

#define IOTEST_DATAMATCH 0xFA
#define IOTEST_NOMATCH   0xCE

#define IOTEST_IOSIZE 128
#define IOTEST_MEMSIZE 2048

static const char *iotest_test[] = {
    "no-eventfd",
    "wildcard-eventfd",
    "datamatch-eventfd"
};

static const char *iotest_type[] = {
    "mmio",
    "portio"
};

#define IOTEST_TEST(i) (iotest_test[((i) % ARRAY_SIZE(iotest_test))])
#define IOTEST_TYPE(i) (iotest_type[((i) / ARRAY_SIZE(iotest_test))])
#define IOTEST_MAX_TEST (ARRAY_SIZE(iotest_test))
#define IOTEST_MAX_TYPE (ARRAY_SIZE(iotest_type))
#define IOTEST_MAX (IOTEST_MAX_TEST * IOTEST_MAX_TYPE)

enum {
    IOTEST_ACCESS_NAME,
    IOTEST_ACCESS_DATA,
    IOTEST_ACCESS_MAX,
};

#define IOTEST_ACCESS_TYPE uint8_t
#define IOTEST_ACCESS_WIDTH (sizeof(uint8_t))

/*
 * DMA Target BAR Protocol
 * This region is RAM-backed so VFIO devices can DMA to it.
 * QEMU polls this region to detect DMA writes.
 */
#define DMA_BAR_MAGIC_OFFSET    0x00
#define DMA_BAR_SEQ_OFFSET      0x04
#define DMA_BAR_POLL_CNT_OFFSET 0x08
#define DMA_BAR_LAST_SEQ_OFFSET 0x0C
#define DMA_BAR_DATA_OFFSET     0x10

/* Extended command offsets for MMIO bridge */
#define DMA_CMD_MAGIC_OFFSET    0x10
#define DMA_CMD_BAR_OFFSET      0x14
#define DMA_CMD_SIZE_OFFSET     0x15
#define DMA_CMD_STATUS_OFFSET   0x16
#define DMA_CMD_OFFSET_OFFSET   0x18
#define DMA_CMD_DATA_OFFSET     0x20
#define DMA_CMD_EXEC_CNT_OFFSET 0x28
#define DMA_CMD_ERROR_OFFSET    0x2C

#define DMA_BAR_MAGIC_VALUE     0xDEADBEEF
#define DMA_CMD_MAGIC_VALUE     0xDEADC0DE
#define DMA_BAR_MIN_SIZE        0x1000  /* 4KB minimum */

/* Command status codes */
#define DMA_CMD_STATUS_PENDING  0
#define DMA_CMD_STATUS_SUCCESS  1
#define DMA_CMD_STATUS_ERROR    2

/* Error codes */
#define DMA_CMD_ERROR_NONE         0
#define DMA_CMD_ERROR_BAR_DISABLED 1
#define DMA_CMD_ERROR_INVALID_BAR  2
#define DMA_CMD_ERROR_INVALID_SIZE 3
#define DMA_CMD_ERROR_OUT_OF_RANGE 4

/*
 * Doorbell DMA Engine
 * Provides a doorbell-based DMA descriptor mechanism in BAR0
 */
#define DOORBELL_OFFSET         0x100  /* Doorbell register base */
#define DOORBELL_REG            0x100  /* Doorbell: write descriptor GPA */
#define DOORBELL_STATUS         0x108  /* Status register (RO) */
#define DOORBELL_ERROR          0x10C  /* Error code (RO) */
#define DOORBELL_READ_COUNT     0x110  /* READ operation counter (RO) */
#define DOORBELL_WRITE_COUNT    0x114  /* WRITE operation counter (RO) */
#define DOORBELL_FILL_COUNT     0x118  /* FILL operation counter (RO) */
#define DOORBELL_ERROR_COUNT    0x11C  /* Error counter (RO) */

#define DOORBELL_DESC_MAGIC     0xDEADBELL  /* Descriptor magic */
#define DOORBELL_COMPLETION_MAGIC 0xDEADBEEFC0DEC0DEULL  /* Completion magic */

/* Doorbell opcodes */
#define DOORBELL_OP_NOP         0
#define DOORBELL_OP_READ        1
#define DOORBELL_OP_WRITE       2
#define DOORBELL_OP_FILL        3

/* Doorbell status codes */
#define DOORBELL_STATUS_IDLE    0
#define DOORBELL_STATUS_BUSY    1
#define DOORBELL_STATUS_DONE    2

/* Doorbell error codes */
#define DOORBELL_ERR_NONE               0
#define DOORBELL_ERR_INVALID_MAGIC      1
#define DOORBELL_ERR_INVALID_OPCODE     2
#define DOORBELL_ERR_INVALID_LENGTH     3
#define DOORBELL_ERR_INVALID_ALIGNMENT  4
#define DOORBELL_ERR_DMA_READ_FAILED    5
#define DOORBELL_ERR_DMA_OP_FAILED      6

typedef struct DMADescriptor {
    uint32_t magic;             /* 0x00: 0xDEADBELL for validation */
    uint8_t  opcode;            /* 0x04: Operation code */
    uint8_t  flags;             /* 0x05: Reserved */
    uint16_t reserved;          /* 0x06: Reserved */
    uint64_t address;           /* 0x08: Guest physical address */
    uint32_t length;            /* 0x10: Number of bytes */
    uint32_t data;              /* 0x14: For FILL: pattern */
    uint64_t completion_addr;   /* 0x18: Where to write completion magic */
} QEMU_PACKED DMADescriptor;

typedef struct DMATargetRegion {
    volatile uint32_t magic;         /* Magic value for validity */
    volatile uint32_t sequence;      /* Sequence number from DMA writer */
    volatile uint32_t poll_count;    /* Number of times QEMU detected changes */
    volatile uint32_t last_sequence; /* Last sequence QEMU saw */
    /* Command structure for MMIO bridge */
    volatile uint32_t cmd_magic;     /* Command magic value */
    volatile uint8_t  cmd_bar;       /* Target BAR number */
    volatile uint8_t  cmd_size;      /* Write size (1,2,4,8) */
    volatile uint16_t cmd_status;    /* Command status */
    volatile uint64_t cmd_offset;    /* Offset in target BAR */
    volatile uint64_t cmd_data;      /* Data to write */
    volatile uint32_t cmd_exec_count;/* Number of commands executed */
    volatile uint32_t cmd_error_code;/* Error code if failed */
    uint8_t padding[0xD0];           /* Reserved */
    uint8_t data[0xF00];             /* Additional data area */
} DMATargetRegion;

struct PCITestDevState {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    MemoryRegion mmio;
    MemoryRegion portio;
    IOTest *tests;
    int current;

    uint64_t membar_size;
    bool membar_backed;
    MemoryRegion membar;

    /* DMA target BAR with polling */
    uint64_t dma_bar_size;
    uint64_t dma_poll_interval;  /* nanoseconds */
    MemoryRegion dma_bar;
    QEMUTimer *dma_poll_timer;
    /* MMIO bridge support */
    bool dma_enable_mmio_bridge;
    uint32_t dma_last_cmd_seq;

    /* Doorbell DMA engine */
    bool doorbell_enabled;
    uint64_t doorbell_max_length;  /* Maximum transfer size */
    uint32_t doorbell_status;      /* Current status */
    uint32_t doorbell_error;       /* Last error code */
    uint32_t doorbell_read_count;  /* Completed READ operations */
    uint32_t doorbell_write_count; /* Completed WRITE operations */
    uint32_t doorbell_fill_count;  /* Completed FILL operations */
    uint32_t doorbell_error_count; /* Failed operations */
    uint8_t *doorbell_buffer;      /* Internal buffer for operations */
    uint64_t doorbell_gpa;         /* Accumulated doorbell GPA */
};

#define TYPE_PCI_TEST_DEV "pci-testdev"

OBJECT_DECLARE_SIMPLE_TYPE(PCITestDevState, PCI_TEST_DEV)

#define IOTEST_IS_MEM(i) (strcmp(IOTEST_TYPE(i), "portio"))
#define IOTEST_REGION(d, i) (IOTEST_IS_MEM(i) ?  &(d)->mmio : &(d)->portio)
#define IOTEST_SIZE(i) (IOTEST_IS_MEM(i) ? IOTEST_MEMSIZE : IOTEST_IOSIZE)
#define IOTEST_PCI_BAR(i) (IOTEST_IS_MEM(i) ? PCI_BASE_ADDRESS_SPACE_MEMORY : \
                           PCI_BASE_ADDRESS_SPACE_IO)

static int pci_testdev_start(IOTest *test)
{
    test->hdr->count = 0;
    if (!test->hasnotifier) {
        return 0;
    }
    event_notifier_test_and_clear(&test->notifier);
    memory_region_add_eventfd(test->mr,
                              le32_to_cpu(test->hdr->offset),
                              test->size,
                              test->match_data,
                              test->hdr->data,
                              &test->notifier);
    return 0;
}

static void pci_testdev_stop(IOTest *test)
{
    if (!test->hasnotifier) {
        return;
    }
    memory_region_del_eventfd(test->mr,
                              le32_to_cpu(test->hdr->offset),
                              test->size,
                              test->match_data,
                              test->hdr->data,
                              &test->notifier);
}

static void
pci_testdev_reset(PCITestDevState *d)
{
    if (d->current == -1 || !d->tests) {
        return;
    }
    pci_testdev_stop(&d->tests[d->current]);
    d->current = -1;
}

static void pci_testdev_inc(IOTest *test, unsigned inc)
{
    uint32_t c = le32_to_cpu(test->hdr->count);
    test->hdr->count = cpu_to_le32(c + inc);
}

/*
 * Execute a doorbell DMA operation
 * Called when guest writes a descriptor GPA to the doorbell register
 */
static void pci_testdev_doorbell_execute(PCITestDevState *d, uint64_t desc_gpa)
{
    DMADescriptor desc;
    MemTxResult result;
    uint64_t completion_magic;
    uint32_t i;

    /* Set status to BUSY */
    d->doorbell_status = DOORBELL_STATUS_BUSY;
    d->doorbell_error = DOORBELL_ERR_NONE;

    /* Read descriptor from guest memory */
    result = address_space_read(&address_space_memory, desc_gpa,
                               MEMTXATTRS_UNSPECIFIED,
                               &desc, sizeof(desc));
    if (result != MEMTX_OK) {
        d->doorbell_error = DOORBELL_ERR_DMA_READ_FAILED;
        goto done;
    }

    /* Convert fields from little-endian */
    desc.magic = le32_to_cpu(desc.magic);
    desc.address = le64_to_cpu(desc.address);
    desc.length = le32_to_cpu(desc.length);
    desc.data = le32_to_cpu(desc.data);
    desc.completion_addr = le64_to_cpu(desc.completion_addr);

    /* Validate magic */
    if (desc.magic != DOORBELL_DESC_MAGIC) {
        d->doorbell_error = DOORBELL_ERR_INVALID_MAGIC;
        goto done;
    }

    /* Execute operation based on opcode */
    switch (desc.opcode) {
    case DOORBELL_OP_NOP:
        /* No operation - just test the mechanism */
        break;

    case DOORBELL_OP_READ:
        /* Validate length for READ */
        if (desc.length == 0 || desc.length > d->doorbell_max_length) {
            d->doorbell_error = DOORBELL_ERR_INVALID_LENGTH;
            goto done;
        }
        /* Read from guest memory into internal buffer */
        result = address_space_read(&address_space_memory, desc.address,
                                   MEMTXATTRS_UNSPECIFIED,
                                   d->doorbell_buffer, desc.length);
        if (result != MEMTX_OK) {
            d->doorbell_error = DOORBELL_ERR_DMA_OP_FAILED;
            goto done;
        }
        d->doorbell_read_count++;
        break;

    case DOORBELL_OP_WRITE:
        /* Validate length for WRITE */
        if (desc.length == 0 || desc.length > d->doorbell_max_length) {
            d->doorbell_error = DOORBELL_ERR_INVALID_LENGTH;
            goto done;
        }
        /* Write test pattern to guest memory */
        for (i = 0; i < desc.length; i++) {
            d->doorbell_buffer[i] = (i & 0xFF);
        }
        result = address_space_write(&address_space_memory, desc.address,
                                    MEMTXATTRS_UNSPECIFIED,
                                    d->doorbell_buffer, desc.length);
        if (result != MEMTX_OK) {
            d->doorbell_error = DOORBELL_ERR_DMA_OP_FAILED;
            goto done;
        }
        d->doorbell_write_count++;
        break;

    case DOORBELL_OP_FILL:
        /* Validate length for FILL */
        if (desc.length == 0 || desc.length > d->doorbell_max_length) {
            d->doorbell_error = DOORBELL_ERR_INVALID_LENGTH;
            goto done;
        }
        /* Fill guest memory with repeating 32-bit pattern */
        for (i = 0; i < desc.length; i += 4) {
            uint32_t pattern = cpu_to_le32(desc.data);
            uint32_t copy_size = MIN(4, desc.length - i);
            memcpy(&d->doorbell_buffer[i], &pattern, copy_size);
        }
        result = address_space_write(&address_space_memory, desc.address,
                                    MEMTXATTRS_UNSPECIFIED,
                                    d->doorbell_buffer, desc.length);
        if (result != MEMTX_OK) {
            d->doorbell_error = DOORBELL_ERR_DMA_OP_FAILED;
            goto done;
        }
        d->doorbell_fill_count++;
        break;

    default:
        d->doorbell_error = DOORBELL_ERR_INVALID_OPCODE;
        goto done;
    }

done:
    /* Update counters */
    if (d->doorbell_error != DOORBELL_ERR_NONE) {
        d->doorbell_error_count++;
    }

    /* Set status to DONE */
    d->doorbell_status = DOORBELL_STATUS_DONE;

    /* Write completion magic if requested (best effort) */
    if (desc.completion_addr != 0) {
        completion_magic = cpu_to_le64(DOORBELL_COMPLETION_MAGIC);
        address_space_write(&address_space_memory, desc.completion_addr,
                          MEMTXATTRS_UNSPECIFIED,
                          &completion_magic, sizeof(completion_magic));
        /* Ignore errors from completion write - operation already done */
    }
}

static void
pci_testdev_write(void *opaque, hwaddr addr, uint64_t val,
                  unsigned size, int type)
{
    PCITestDevState *d = opaque;
    IOTest *test;
    int t, r;

    /*
     * Handle doorbell register write (0x100-0x107 for 8-byte value)
     * Accumulate partial writes into 64-bit GPA
     */
    if (d->doorbell_enabled && addr >= DOORBELL_REG && addr < DOORBELL_STATUS) {
        if (addr == DOORBELL_REG && (size == 4 || size == 8)) {
            /* Lower 32 bits */
            d->doorbell_gpa = (d->doorbell_gpa & 0xFFFFFFFF00000000ULL) |
                             (val & 0xFFFFFFFFULL);
            if (size == 8) {
                /* Full 8-byte write - trigger immediately */
                pci_testdev_doorbell_execute(d, val);
            }
        } else if (addr == (DOORBELL_REG + 4) && size == 4) {
            /* Upper 32 bits - complete 64-bit write and trigger */
            d->doorbell_gpa = (d->doorbell_gpa & 0xFFFFFFFFULL) |
                             ((uint64_t)val << 32);
            pci_testdev_doorbell_execute(d, d->doorbell_gpa);
        }
        return;
    }

    /* Doorbell registers are read-only (except doorbell itself) */
    if (d->doorbell_enabled && addr >= DOORBELL_OFFSET && addr < 0x120) {
        return;  /* Ignore writes to RO registers */
    }

    /* Original test device logic */
    if (addr == offsetof(PCITestDevHdr, test)) {
        pci_testdev_reset(d);
        if (val >= IOTEST_MAX_TEST) {
            return;
        }
        t = type * IOTEST_MAX_TEST + val;
        r = pci_testdev_start(&d->tests[t]);
        if (r < 0) {
            return;
        }
        d->current = t;
        return;
    }
    if (d->current < 0) {
        return;
    }
    test = &d->tests[d->current];
    if (addr != le32_to_cpu(test->hdr->offset)) {
        return;
    }
    if (test->match_data && test->size != size) {
        return;
    }
    if (test->match_data && val != test->hdr->data) {
        return;
    }
    pci_testdev_inc(test, 1);
}

static uint64_t
pci_testdev_read(void *opaque, hwaddr addr, unsigned size)
{
    PCITestDevState *d = opaque;
    const char *buf;
    IOTest *test;

    /* Handle doorbell registers (0x100-0x11F) */
    if (d->doorbell_enabled && addr >= DOORBELL_OFFSET && addr < 0x120) {
        /* Handle 4-byte aligned reads for the registers */
        if (size == 4 || size == 1) {
            switch (addr) {
            case DOORBELL_REG:
            case DOORBELL_REG + 4:
                return 0;  /* Doorbell is write-only */
            case DOORBELL_STATUS:
                return d->doorbell_status;
            case DOORBELL_ERROR:
                return d->doorbell_error;
            case DOORBELL_READ_COUNT:
                return d->doorbell_read_count;
            case DOORBELL_WRITE_COUNT:
                return d->doorbell_write_count;
            case DOORBELL_FILL_COUNT:
                return d->doorbell_fill_count;
            case DOORBELL_ERROR_COUNT:
                return d->doorbell_error_count;
            default:
                return 0;  /* Reserved */
            }
        }
        return 0;
    }

    /* Original test device logic */
    if (d->current < 0) {
        return 0;
    }
    test = &d->tests[d->current];
    buf = (const char *)test->hdr;
    if (addr + size >= test->bufsize) {
        return 0;
    }
    if (test->hasnotifier) {
        event_notifier_test_and_clear(&test->notifier);
    }
    return buf[addr];
}

static void
pci_testdev_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                       unsigned size)
{
    pci_testdev_write(opaque, addr, val, size, 0);
}

static void
pci_testdev_pio_write(void *opaque, hwaddr addr, uint64_t val,
                       unsigned size)
{
    pci_testdev_write(opaque, addr, val, size, 1);
}

static const MemoryRegionOps pci_testdev_mmio_ops = {
    .read = pci_testdev_read,
    .write = pci_testdev_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,  /* Support 8-byte for doorbell */
    },
};

static const MemoryRegionOps pci_testdev_pio_ops = {
    .read = pci_testdev_read,
    .write = pci_testdev_pio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 1,
    },
};

/*
 * Poll the DMA target BAR for changes
 * This detects when a VFIO device has written to the RAM-backed BAR
 */
static void pci_testdev_dma_poll(void *opaque)
{
    PCITestDevState *d = PCI_TEST_DEV(opaque);
    DMATargetRegion *dma_region;
    uint32_t current_magic, current_seq, last_seq;

    if (!d->dma_bar_size) {
        return;
    }

    /* Get pointer to RAM backing the DMA BAR */
    dma_region = (DMATargetRegion *)memory_region_get_ram_ptr(&d->dma_bar);

    /* Read current values */
    current_magic = qatomic_read(&dma_region->magic);
    current_seq = qatomic_read(&dma_region->sequence);
    last_seq = qatomic_read(&dma_region->last_sequence);

    /*
     * Detect write: valid magic and sequence number changed
     * Note: Using volatile pointers and atomic reads to ensure we see
     * DMA writes from VFIO devices (which bypass QEMU entirely)
     */
    /* Basic polling: detect any DMA write */
    if (current_magic == DMA_BAR_MAGIC_VALUE && current_seq != last_seq) {
        uint32_t poll_count = qatomic_read(&dma_region->poll_count);

        /* Update poll count and last sequence */
        qatomic_set(&dma_region->poll_count, poll_count + 1);
        qatomic_set(&dma_region->last_sequence, current_seq);
    }

    /* MMIO Bridge: execute commands to trigger BAR MMIO callbacks */
    if (d->dma_enable_mmio_bridge) {
        uint32_t cmd_magic = qatomic_read(&dma_region->cmd_magic);
        uint16_t cmd_status;
        uint8_t cmd_bar, cmd_size;
        uint64_t cmd_offset, cmd_data;
        MemoryRegion *target_mr = NULL;
        MemTxResult result;

        /* Check for valid command */
        if (cmd_magic != DMA_CMD_MAGIC_VALUE) {
            goto reschedule;
        }

        /* Check if this is a new command */
        if (current_seq == d->dma_last_cmd_seq) {
            goto reschedule;
        }

        cmd_status = qatomic_read(&dma_region->cmd_status);
        if (cmd_status != DMA_CMD_STATUS_PENDING) {
            goto reschedule;
        }

        /* Read command parameters */
        cmd_bar = qatomic_read(&dma_region->cmd_bar);
        cmd_size = qatomic_read(&dma_region->cmd_size);
        cmd_offset = qatomic_read(&dma_region->cmd_offset);
        cmd_data = qatomic_read(&dma_region->cmd_data);

        /* Determine target BAR */
        switch (cmd_bar) {
        case 0:
            target_mr = &d->mmio;
            break;
        case 1:
            target_mr = &d->portio;
            break;
        case 2:
            if (d->membar_size > 0) {
                target_mr = &d->membar;
            } else {
                qatomic_set(&dma_region->cmd_status, DMA_CMD_STATUS_ERROR);
                qatomic_set(&dma_region->cmd_error_code,
                           DMA_CMD_ERROR_BAR_DISABLED);
                goto reschedule;
            }
            break;
        default:
            qatomic_set(&dma_region->cmd_status, DMA_CMD_STATUS_ERROR);
            qatomic_set(&dma_region->cmd_error_code,
                       DMA_CMD_ERROR_INVALID_BAR);
            goto reschedule;
        }

        /* Validate size */
        if (cmd_size != 1 && cmd_size != 2 && cmd_size != 4 &&
            cmd_size != 8) {
            qatomic_set(&dma_region->cmd_status, DMA_CMD_STATUS_ERROR);
            qatomic_set(&dma_region->cmd_error_code,
                       DMA_CMD_ERROR_INVALID_SIZE);
            goto reschedule;
        }

        /* Execute MMIO write - THIS TRIGGERS THE BAR CALLBACKS! */
        result = memory_region_dispatch_write(target_mr, cmd_offset, cmd_data,
                                             size_memop(cmd_size) | MO_LE,
                                             MEMTXATTRS_UNSPECIFIED);

        /* Update status */
        if (result == MEMTX_OK) {
            qatomic_set(&dma_region->cmd_status, DMA_CMD_STATUS_SUCCESS);
            uint32_t exec_count = qatomic_read(&dma_region->cmd_exec_count);
            qatomic_set(&dma_region->cmd_exec_count, exec_count + 1);
        } else {
            qatomic_set(&dma_region->cmd_status, DMA_CMD_STATUS_ERROR);
            qatomic_set(&dma_region->cmd_error_code,
                       DMA_CMD_ERROR_OUT_OF_RANGE);
        }

        d->dma_last_cmd_seq = current_seq;
    }

reschedule:
    /* Re-arm timer */
    timer_mod(d->dma_poll_timer,
              qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + d->dma_poll_interval);
}

/*
 * Initialize DMA target BAR
 */
static void pci_testdev_init_dma_bar(PCITestDevState *d, Error **errp)
{
    if (d->dma_bar_size < DMA_BAR_MIN_SIZE) {
        error_setg(errp, "dma-bar-size must be at least %u bytes",
                   DMA_BAR_MIN_SIZE);
        return;
    }

    /* Create RAM-backed region - use memory_region_init_ram instead */
    memory_region_init_ram(&d->dma_bar, OBJECT(d),
                          "pci-testdev-dma-target",
                          d->dma_bar_size, errp);
    if (*errp) {
        return;
    }

    /* Set up polling timer */
    d->dma_poll_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                                      pci_testdev_dma_poll, d);
    if (d->dma_poll_interval > 0) {
        timer_mod(d->dma_poll_timer,
                  qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + d->dma_poll_interval);
    }
}

static void pci_testdev_realize(PCIDevice *pci_dev, Error **errp)
{
    PCITestDevState *d = PCI_TEST_DEV(pci_dev);
    uint8_t *pci_conf;
    char *name;
    int r, i;

    /* Validate DMA polling interval */
    if (d->dma_bar_size && d->dma_poll_interval == 0) {
        /* Default to 10μs polling interval */
        d->dma_poll_interval = 10000;
    }

    if (d->dma_bar_size && d->dma_poll_interval < 1000) {
        error_setg(errp, "dma-poll-interval must be at least 1000ns (1μs)");
        return;
    }

    pci_conf = pci_dev->config;

    pci_conf[PCI_INTERRUPT_PIN] = 0; /* no interrupt pin */

    memory_region_init_io(&d->mmio, OBJECT(d), &pci_testdev_mmio_ops, d,
                          "pci-testdev-mmio", IOTEST_MEMSIZE * 2);
    memory_region_init_io(&d->portio, OBJECT(d), &pci_testdev_pio_ops, d,
                          "pci-testdev-portio", IOTEST_IOSIZE * 2);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);
    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->portio);

    if (d->membar_size) {
        if (d->membar_backed)
            memory_region_init_ram(&d->membar, OBJECT(d),
                                   "pci-testdev-membar-backed",
                                   d->membar_size, NULL);
        else
            memory_region_init(&d->membar, OBJECT(d),
                               "pci-testdev-membar",
                               d->membar_size);
        pci_register_bar(pci_dev, 2,
                         PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_PREFETCH |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                         &d->membar);
    }

    /* Set up DMA target BAR if requested */
    if (d->dma_bar_size) {
        pci_testdev_init_dma_bar(d, errp);
        if (*errp) {
            return;
        }
        pci_register_bar(pci_dev, 3,
                         PCI_BASE_ADDRESS_SPACE_MEMORY |
                         PCI_BASE_ADDRESS_MEM_PREFETCH |
                         PCI_BASE_ADDRESS_MEM_TYPE_64,
                         &d->dma_bar);
    }

    /* Initialize doorbell DMA engine if enabled */
    if (d->doorbell_enabled) {
        if (d->doorbell_max_length == 0) {
            d->doorbell_max_length = 4096;  /* Default 4KB */
        }
        d->doorbell_buffer = g_malloc0(d->doorbell_max_length);
        d->doorbell_status = DOORBELL_STATUS_IDLE;
        d->doorbell_error = DOORBELL_ERR_NONE;
        d->doorbell_read_count = 0;
        d->doorbell_write_count = 0;
        d->doorbell_fill_count = 0;
        d->doorbell_error_count = 0;
    }

    d->current = -1;
    d->tests = g_malloc0(IOTEST_MAX * sizeof *d->tests);
    for (i = 0; i < IOTEST_MAX; ++i) {
        IOTest *test = &d->tests[i];
        name = g_strdup_printf("%s-%s", IOTEST_TYPE(i), IOTEST_TEST(i));
        test->bufsize = sizeof(PCITestDevHdr) + strlen(name) + 1;
        test->hdr = g_malloc0(test->bufsize);
        memcpy(test->hdr->name, name, strlen(name) + 1);
        g_free(name);
        test->hdr->offset = cpu_to_le32(IOTEST_SIZE(i) + i * IOTEST_ACCESS_WIDTH);
        test->match_data = strcmp(IOTEST_TEST(i), "wildcard-eventfd");
        if (IOTEST_IS_MEM(i) && !test->match_data) {
            test->size = 0;
        } else {
            test->size = IOTEST_ACCESS_WIDTH;
        }
        test->hdr->test = i;
        test->hdr->data = test->match_data ? IOTEST_DATAMATCH : IOTEST_NOMATCH;
        test->hdr->width = IOTEST_ACCESS_WIDTH;
        test->mr = IOTEST_REGION(d, i);
        if (!strcmp(IOTEST_TEST(i), "no-eventfd")) {
            test->hasnotifier = false;
            continue;
        }
        r = event_notifier_init(&test->notifier, 0);
        assert(r >= 0);
        test->hasnotifier = true;
    }
}

static void
pci_testdev_uninit(PCIDevice *dev)
{
    PCITestDevState *d = PCI_TEST_DEV(dev);
    int i;

    if (d->dma_poll_timer) {
        timer_free(d->dma_poll_timer);
        d->dma_poll_timer = NULL;
    }

    if (d->doorbell_buffer) {
        g_free(d->doorbell_buffer);
        d->doorbell_buffer = NULL;
    }

    pci_testdev_reset(d);
    for (i = 0; i < IOTEST_MAX; ++i) {
        if (d->tests[i].hasnotifier) {
            event_notifier_cleanup(&d->tests[i].notifier);
        }
        g_free(d->tests[i].hdr);
    }
    g_free(d->tests);
}

static void qdev_pci_testdev_reset(DeviceState *dev)
{
    PCITestDevState *d = PCI_TEST_DEV(dev);
    pci_testdev_reset(d);

    /* Reset doorbell counters */
    if (d->doorbell_enabled) {
        d->doorbell_status = DOORBELL_STATUS_IDLE;
        d->doorbell_error = DOORBELL_ERR_NONE;
        d->doorbell_read_count = 0;
        d->doorbell_write_count = 0;
        d->doorbell_fill_count = 0;
        d->doorbell_error_count = 0;
    }
}

static const Property pci_testdev_properties[] = {
    DEFINE_PROP_SIZE("membar", PCITestDevState, membar_size, 0),
    DEFINE_PROP_BOOL("membar-backed", PCITestDevState, membar_backed, false),
    DEFINE_PROP_SIZE("dma-bar-size", PCITestDevState, dma_bar_size, 0),
    /*
     * Polling interval in nanoseconds. Default 10000ns = 10μs.
     * Lower values = lower latency but higher overhead.
     * Set to 0 to disable automatic polling.
     */
    DEFINE_PROP_UINT64("dma-poll-interval", PCITestDevState,
                       dma_poll_interval, 10000),
    /*
     * Enable MMIO bridge: allows DMA commands in BAR3 to trigger
     * MMIO writes to other BARs (e.g., BAR0).
     */
    DEFINE_PROP_BOOL("dma-mmio-bridge", PCITestDevState,
                     dma_enable_mmio_bridge, false),
    /*
     * Enable doorbell DMA engine: provides doorbell-based descriptor
     * mechanism in BAR0 for testing DMA operations.
     */
    DEFINE_PROP_BOOL("doorbell-dma", PCITestDevState,
                     doorbell_enabled, false),
    DEFINE_PROP_SIZE("doorbell-dma-max", PCITestDevState,
                     doorbell_max_length, 4096),
};

static void pci_testdev_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_testdev_realize;
    k->exit = pci_testdev_uninit;
    k->vendor_id = PCI_VENDOR_ID_REDHAT;
    k->device_id = PCI_DEVICE_ID_REDHAT_TEST;
    k->revision = 0x00;
    k->class_id = PCI_CLASS_OTHERS;
    dc->desc = "PCI Test Device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_legacy_reset(dc, qdev_pci_testdev_reset);
    device_class_set_props(dc, pci_testdev_properties);
}

static const TypeInfo pci_testdev_info = {
    .name          = TYPE_PCI_TEST_DEV,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PCITestDevState),
    .class_init    = pci_testdev_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static void pci_testdev_register_types(void)
{
    type_register_static(&pci_testdev_info);
}

type_init(pci_testdev_register_types)
