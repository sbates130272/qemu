/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcase for pci-testdev Doorbell DMA Engine
 *
 * Copyright (c) 2025 Stephen Bates
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "hw/pci/pci_regs.h"
#include "qemu/bswap.h"

#define PCI_VENDOR_ID_REDHAT    0x1b36
#define PCI_DEVICE_ID_TESTDEV   0x0005

/* Doorbell registers in BAR0 */
#define DOORBELL_REG            0x100
#define DOORBELL_STATUS         0x108
#define DOORBELL_ERROR          0x10C
#define DOORBELL_READ_COUNT     0x110
#define DOORBELL_WRITE_COUNT    0x114
#define DOORBELL_FILL_COUNT     0x118
#define DOORBELL_ERROR_COUNT    0x11C

/* Doorbell magic values */
#define DOORBELL_DESC_MAGIC     0xDEADBELL
#define DOORBELL_COMPLETION_MAGIC 0xDEADBEEFC0DEC0DEULL

/* Doorbell opcodes */
#define DOORBELL_OP_NOP         0
#define DOORBELL_OP_READ        1
#define DOORBELL_OP_WRITE       2
#define DOORBELL_OP_FILL        3

/* Status codes */
#define DOORBELL_STATUS_IDLE    0
#define DOORBELL_STATUS_BUSY    1
#define DOORBELL_STATUS_DONE    2

/* Place device at slot 4 */
#define TESTDEV_PCI_SLOT 0x4

typedef struct {
    uint32_t magic;
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t reserved;
    uint64_t address;
    uint32_t length;
    uint32_t data;
    uint64_t completion_addr;
} QEMU_PACKED DMADescriptor;

/*
 * Test NOP operation
 */
static void test_doorbell_nop(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar0;
    DMADescriptor desc;
    uint64_t desc_gpa;
    uint64_t completion = 0;
    uint32_t status, error;

    qts = qtest_init("-device pci-testdev,addr=04.0,doorbell-dma=on");
    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);
    bar0 = qpci_iomap(dev, 0, NULL);

    /* Prepare descriptor in guest memory */
    desc_gpa = 0x10000;  /* Use fixed guest address */
    memset(&desc, 0, sizeof(desc));
    desc.magic = cpu_to_le32(DOORBELL_DESC_MAGIC);
    desc.opcode = DOORBELL_OP_NOP;
    desc.completion_addr = cpu_to_le64(desc_gpa + 0x100);  /* Use offset */

    qtest_memwrite(qts, desc_gpa, &desc, sizeof(desc));

    /* Ring doorbell */
    qpci_io_writeq(dev, bar0, DOORBELL_REG, desc_gpa);

    /* Wait a bit for operation */
    qtest_clock_step(qts, 1000000);

    /* Check status */
    status = qpci_io_readl(dev, bar0, DOORBELL_STATUS);
    error = qpci_io_readl(dev, bar0, DOORBELL_ERROR);

    g_assert_cmpuint(status, ==, DOORBELL_STATUS_DONE);
    g_assert_cmpuint(error, ==, 0);

    /* Check completion magic */
    qtest_memread(qts, desc_gpa + 0x100, &completion, sizeof(completion));
    completion = le64_to_cpu(completion);
    g_assert_cmpuint(completion, ==, DOORBELL_COMPLETION_MAGIC);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test FILL operation
 */
static void test_doorbell_fill(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar0;
    DMADescriptor desc;
    uint64_t desc_gpa, target_gpa, completion_gpa;
    uint64_t completion = 0;
    uint32_t pattern = 0xCAFEBABE;
    uint32_t read_data[4];
    uint32_t fill_count;
    uint32_t val;
    int i;

    qts = qtest_init("-device pci-testdev,addr=04.0,doorbell-dma=on");
    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);
    bar0 = qpci_iomap(dev, 0, NULL);

    /* Use fixed guest memory addresses */
    desc_gpa = 0x10000;
    target_gpa = desc_gpa + 0x100;
    completion_gpa = desc_gpa + 0x200;

    /* Prepare descriptor */
    memset(&desc, 0, sizeof(desc));
    desc.magic = cpu_to_le32(DOORBELL_DESC_MAGIC);
    desc.opcode = DOORBELL_OP_FILL;
    desc.address = cpu_to_le64(target_gpa);
    desc.length = cpu_to_le32(16);
    desc.data = cpu_to_le32(pattern);
    desc.completion_addr = cpu_to_le64(completion_gpa);

    qtest_memwrite(qts, desc_gpa, &desc, sizeof(desc));

    /* Ring doorbell */
    qpci_io_writeq(dev, bar0, DOORBELL_REG, desc_gpa);

    /* Wait for completion */
    qtest_clock_step(qts, 1000000);

    /* Check completion */
    qtest_memread(qts, completion_gpa, &completion, sizeof(completion));
    completion = le64_to_cpu(completion);
    g_assert_cmpuint(completion, ==, DOORBELL_COMPLETION_MAGIC);

    /* Verify fill pattern */
    qtest_memread(qts, target_gpa, read_data, sizeof(read_data));
    for (i = 0; i < 4; i++) {
        val = le32_to_cpu(read_data[i]);
        g_assert_cmpuint(val, ==, pattern);
    }

    /* Check counter */
    fill_count = qpci_io_readl(dev, bar0, DOORBELL_FILL_COUNT);
    g_assert_cmpuint(fill_count, ==, 1);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test READ operation
 */
static void test_doorbell_read(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar0;
    DMADescriptor desc;
    uint64_t desc_gpa, source_gpa, completion_gpa;
    uint64_t completion = 0;
    uint32_t test_data[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444};
    uint32_t read_count, error;

    qts = qtest_init("-device pci-testdev,addr=04.0,doorbell-dma=on");
    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);
    bar0 = qpci_iomap(dev, 0, NULL);

    /* Use fixed guest memory addresses */
    desc_gpa = 0x10000;
    source_gpa = desc_gpa + 0x100;
    completion_gpa = desc_gpa + 0x200;

    qtest_memwrite(qts, source_gpa, test_data, sizeof(test_data));

    /* Prepare descriptor */
    memset(&desc, 0, sizeof(desc));
    desc.magic = cpu_to_le32(DOORBELL_DESC_MAGIC);
    desc.opcode = DOORBELL_OP_READ;
    desc.address = cpu_to_le64(source_gpa);
    desc.length = cpu_to_le32(16);
    desc.completion_addr = cpu_to_le64(completion_gpa);

    qtest_memwrite(qts, desc_gpa, &desc, sizeof(desc));

    /* Ring doorbell */
    qpci_io_writeq(dev, bar0, DOORBELL_REG, desc_gpa);

    /* Wait for completion */
    qtest_clock_step(qts, 1000000);

    /* Check completion and error */
    qtest_memread(qts, completion_gpa, &completion, sizeof(completion));
    completion = le64_to_cpu(completion);
    error = qpci_io_readl(dev, bar0, DOORBELL_ERROR);
    g_assert_cmpuint(completion, ==, DOORBELL_COMPLETION_MAGIC);
    g_assert_cmpuint(error, ==, 0);

    /* Check counter */
    read_count = qpci_io_readl(dev, bar0, DOORBELL_READ_COUNT);
    g_assert_cmpuint(read_count, ==, 1);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test invalid magic
 */
static void test_doorbell_invalid_magic(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar0;
    DMADescriptor desc;
    uint64_t desc_gpa;
    uint32_t error, error_count;

    qts = qtest_init("-device pci-testdev,addr=04.0,doorbell-dma=on");
    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);
    bar0 = qpci_iomap(dev, 0, NULL);

    desc_gpa = 0x10000;

    /* Prepare descriptor with bad magic */
    memset(&desc, 0, sizeof(desc));
    desc.magic = cpu_to_le32(0xBADBAD00);
    desc.opcode = DOORBELL_OP_NOP;
    qtest_memwrite(qts, desc_gpa, &desc, sizeof(desc));

    /* Ring doorbell */
    qpci_io_writeq(dev, bar0, DOORBELL_REG, desc_gpa);
    qtest_clock_step(qts, 1000000);

    /* Check error */
    error = qpci_io_readl(dev, bar0, DOORBELL_ERROR);
    error_count = qpci_io_readl(dev, bar0, DOORBELL_ERROR_COUNT);
    g_assert_cmpuint(error, ==, 1);  /* INVALID_MAGIC */
    g_assert_cmpuint(error_count, ==, 1);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test disabled doorbell (should not crash)
 */
static void test_doorbell_disabled(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar0;
    uint32_t status;

    /* Don't enable doorbell-dma */
    qts = qtest_init("-device pci-testdev,addr=04.0");
    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);
    bar0 = qpci_iomap(dev, 0, NULL);

    /* Try to read status register - should return 0 */
    status = qpci_io_readl(dev, bar0, DOORBELL_STATUS);
    g_assert_cmpuint(status, ==, 0);

    /* Writing to doorbell should be ignored */
    qpci_io_writeq(dev, bar0, DOORBELL_REG, 0x1000);
    qtest_clock_step(qts, 1000000);

    /* Still should be 0 */
    status = qpci_io_readl(dev, bar0, DOORBELL_STATUS);
    g_assert_cmpuint(status, ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/pci-testdev-doorbell/nop", test_doorbell_nop);
    qtest_add_func("/pci-testdev-doorbell/fill", test_doorbell_fill);
    qtest_add_func("/pci-testdev-doorbell/read", test_doorbell_read);
    qtest_add_func("/pci-testdev-doorbell/invalid-magic",
                   test_doorbell_invalid_magic);
    qtest_add_func("/pci-testdev-doorbell/disabled",
                   test_doorbell_disabled);

    return g_test_run();
}

