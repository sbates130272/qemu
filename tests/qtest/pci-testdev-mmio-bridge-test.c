/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcase for pci-testdev MMIO bridge (BAR3→BAR0)
 *
 * Copyright (c) 2025 Stephen Bates
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "hw/pci/pci_regs.h"
#include "qemu/timer.h"

#define PCI_VENDOR_ID_REDHAT    0x1b36
#define PCI_DEVICE_ID_TESTDEV   0x0005

/* DMA Target BAR Protocol */
#define DMA_BAR_MAGIC_OFFSET    0x00
#define DMA_BAR_SEQ_OFFSET      0x04
#define DMA_BAR_POLL_CNT_OFFSET 0x08
#define DMA_BAR_LAST_SEQ_OFFSET 0x0C

/* Command offsets in BAR3 */
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
#define DMA_BAR_NUM             3

/* Command status */
#define DMA_CMD_STATUS_PENDING  0
#define DMA_CMD_STATUS_SUCCESS  1
#define DMA_CMD_STATUS_ERROR    2

/* Error codes */
#define DMA_CMD_ERROR_BAR_DISABLED 1
#define DMA_CMD_ERROR_INVALID_BAR  2
#define DMA_CMD_ERROR_INVALID_SIZE 3

/* BAR0 offsets (pci-testdev MMIO) */
#define BAR0_TEST_OFFSET        0x00
#define BAR0_WIDTH_OFFSET       0x01
#define BAR0_OFFSET_OFFSET      0x04
#define BAR0_DATA_OFFSET        0x08
#define BAR0_COUNT_OFFSET       0x0C

/* Place device at slot 4 like other tests do */
#define TESTDEV_PCI_SLOT 0x4

/*
 * Execute a command and wait for completion
 */
static bool execute_command(QPCIDevice *dev, QPCIBar bar3, QTestState *qts,
                           uint8_t target_bar, uint8_t size,
                           uint64_t offset, uint64_t data,
                           uint16_t *status_out, uint32_t *error_out)
{
    uint32_t seq;
    uint16_t status;
    int retries = 100;

    /* Write command parameters */
    qpci_io_writeb(dev, bar3, DMA_CMD_BAR_OFFSET, target_bar);
    qpci_io_writeb(dev, bar3, DMA_CMD_SIZE_OFFSET, size);
    qpci_io_writeq(dev, bar3, DMA_CMD_OFFSET_OFFSET, offset);
    qpci_io_writeq(dev, bar3, DMA_CMD_DATA_OFFSET, data);
    qpci_io_writew(dev, bar3, DMA_CMD_STATUS_OFFSET,
                   DMA_CMD_STATUS_PENDING);

    /* Increment sequence to trigger */
    seq = qpci_io_readl(dev, bar3, DMA_BAR_SEQ_OFFSET);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, seq + 1);

    /* Wait for completion */
    do {
        qtest_clock_step(qts, 1000000); /* 1ms */
        status = qpci_io_readw(dev, bar3, DMA_CMD_STATUS_OFFSET);
    } while (status == DMA_CMD_STATUS_PENDING && --retries > 0);

    if (status_out) {
        *status_out = status;
    }
    if (error_out) {
        *error_out = qpci_io_readl(dev, bar3, DMA_CMD_ERROR_OFFSET);
    }

    return status != DMA_CMD_STATUS_PENDING;
}

/*
 * Test basic command execution to BAR0
 */
static void test_mmio_bridge_basic(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar0, bar3;
    uint16_t status;
    uint32_t error, exec_count_before, exec_count_after;
    uint8_t test_val;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-mmio-bridge=on");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar0 = qpci_iomap(dev, 0, NULL);
    bar3 = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Initialize BAR3 */
    qpci_io_writel(dev, bar3, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, 0);
    qpci_io_writel(dev, bar3, DMA_CMD_MAGIC_OFFSET, DMA_CMD_MAGIC_VALUE);

    exec_count_before = qpci_io_readl(dev, bar3, DMA_CMD_EXEC_CNT_OFFSET);

    /* Execute command: write 0x02 to BAR0 offset 0x00 (test register) */
    g_assert(execute_command(dev, bar3, qts, 0, 1, BAR0_TEST_OFFSET, 0x02,
                            &status, &error));

    g_assert_cmpuint(status, ==, DMA_CMD_STATUS_SUCCESS);
    g_assert_cmpuint(error, ==, 0);

    exec_count_after = qpci_io_readl(dev, bar3, DMA_CMD_EXEC_CNT_OFFSET);
    g_assert_cmpuint(exec_count_after, ==, exec_count_before + 1);

    /* Verify the write took effect */
    test_val = qpci_io_readb(dev, bar0, BAR0_TEST_OFFSET);
    g_assert_cmpuint(test_val, ==, 0x02);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test error handling: invalid BAR number
 */
static void test_mmio_bridge_invalid_bar(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar3;
    uint16_t status;
    uint32_t error;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-mmio-bridge=on");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar3 = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Initialize */
    qpci_io_writel(dev, bar3, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, 0);
    qpci_io_writel(dev, bar3, DMA_CMD_MAGIC_OFFSET, DMA_CMD_MAGIC_VALUE);

    /* Try to write to invalid BAR 99 */
    g_assert(execute_command(dev, bar3, qts, 99, 1, 0x00, 0xFF,
                            &status, &error));

    g_assert_cmpuint(status, ==, DMA_CMD_STATUS_ERROR);
    g_assert_cmpuint(error, ==, DMA_CMD_ERROR_INVALID_BAR);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test error handling: invalid write size
 */
static void test_mmio_bridge_invalid_size(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar3;
    uint16_t status;
    uint32_t error;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-mmio-bridge=on");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar3 = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Initialize */
    qpci_io_writel(dev, bar3, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, 0);
    qpci_io_writel(dev, bar3, DMA_CMD_MAGIC_OFFSET, DMA_CMD_MAGIC_VALUE);

    /* Try invalid size 3 */
    g_assert(execute_command(dev, bar3, qts, 0, 3, 0x00, 0xFF,
                            &status, &error));

    g_assert_cmpuint(status, ==, DMA_CMD_STATUS_ERROR);
    g_assert_cmpuint(error, ==, DMA_CMD_ERROR_INVALID_SIZE);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test multiple sequential commands
 * We verify that multiple commands are executed by checking exec_count.
 * Note: pci-testdev doesn't implement general-purpose MMIO storage,
 * so we can't verify data persistence. The key test is that the MMIO
 * callbacks are triggered (exec_count increases) without errors.
 */
static void test_mmio_bridge_multiple(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar3;
    uint16_t status;
    uint32_t error, exec_count;
    int i;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-mmio-bridge=on");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar3 = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Initialize */
    qpci_io_writel(dev, bar3, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, 0);
    qpci_io_writel(dev, bar3, DMA_CMD_MAGIC_OFFSET, DMA_CMD_MAGIC_VALUE);

    /* Execute multiple commands */
    for (i = 0; i < 5; i++) {
        /*
         * Write to offset 0x01 (width). We don't verify the write took
         * effect because pci-testdev doesn't store arbitrary values.
         * The important part is that each command succeeds (status=SUCCESS)
         * and exec_count increases.
         */
        g_assert(execute_command(dev, bar3, qts, 0, 1, BAR0_WIDTH_OFFSET,
                                0x42 + i, &status, &error));
        g_assert_cmpuint(status, ==, DMA_CMD_STATUS_SUCCESS);
        g_assert_cmpuint(error, ==, 0);
    }

    /* Verify all 5 commands were executed */
    exec_count = qpci_io_readl(dev, bar3, DMA_CMD_EXEC_CNT_OFFSET);
    g_assert_cmpuint(exec_count, ==, 5);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test that bridge is disabled without dma-mmio-bridge=on
 */
static void test_mmio_bridge_disabled(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar3;
    uint32_t seq;
    uint16_t status;

    /* Don't enable dma-mmio-bridge */
    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar3 = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Initialize */
    qpci_io_writel(dev, bar3, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, 0);
    qpci_io_writel(dev, bar3, DMA_CMD_MAGIC_OFFSET, DMA_CMD_MAGIC_VALUE);
    qpci_io_writew(dev, bar3, DMA_CMD_STATUS_OFFSET,
                   DMA_CMD_STATUS_PENDING);

    /* Write command */
    qpci_io_writeb(dev, bar3, DMA_CMD_BAR_OFFSET, 0);
    qpci_io_writeb(dev, bar3, DMA_CMD_SIZE_OFFSET, 1);
    qpci_io_writeq(dev, bar3, DMA_CMD_OFFSET_OFFSET, 0x00);
    qpci_io_writeq(dev, bar3, DMA_CMD_DATA_OFFSET, 0x02);

    seq = qpci_io_readl(dev, bar3, DMA_BAR_SEQ_OFFSET);
    qpci_io_writel(dev, bar3, DMA_BAR_SEQ_OFFSET, seq + 1);

    /* Wait */
    qtest_clock_step(qts, 100000000); /* 100ms */

    /* Status should still be PENDING (bridge disabled) */
    status = qpci_io_readw(dev, bar3, DMA_CMD_STATUS_OFFSET);
    g_assert_cmpuint(status, ==, DMA_CMD_STATUS_PENDING);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/pci-testdev-mmio-bridge/basic",
                   test_mmio_bridge_basic);
    qtest_add_func("/pci-testdev-mmio-bridge/invalid-bar",
                   test_mmio_bridge_invalid_bar);
    qtest_add_func("/pci-testdev-mmio-bridge/invalid-size",
                   test_mmio_bridge_invalid_size);
    qtest_add_func("/pci-testdev-mmio-bridge/multiple",
                   test_mmio_bridge_multiple);
    qtest_add_func("/pci-testdev-mmio-bridge/disabled",
                   test_mmio_bridge_disabled);

    return g_test_run();
}

