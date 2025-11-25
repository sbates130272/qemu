/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcase for pci-testdev DMA polling
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
#define DMA_BAR_DATA_OFFSET     0x10

#define DMA_BAR_MAGIC_VALUE     0xDEADBEEF
#define DMA_BAR_NUM             3

/* Place device at slot 4 like other tests do */
#define TESTDEV_PCI_SLOT 0x4

/*
 * Test basic DMA target BAR initialization
 */
static void test_dma_bar_init(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar;
    uint32_t magic, sequence, poll_count, last_seq;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096");
    pcibus = qpci_new_pc(qts, NULL);

    /* Find pci-testdev at slot 4 */
    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    g_assert_cmpuint(qpci_config_readw(dev, PCI_VENDOR_ID), ==,
                     PCI_VENDOR_ID_REDHAT);
    g_assert_cmpuint(qpci_config_readw(dev, PCI_DEVICE_ID), ==,
                     PCI_DEVICE_ID_TESTDEV);

    qpci_device_enable(dev);

    /* Map BAR 3 (DMA target) */
    bar = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Check initial state - all zeros */
    magic = qpci_io_readl(dev, bar, DMA_BAR_MAGIC_OFFSET);
    sequence = qpci_io_readl(dev, bar, DMA_BAR_SEQ_OFFSET);
    poll_count = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);
    last_seq = qpci_io_readl(dev, bar, DMA_BAR_LAST_SEQ_OFFSET);

    g_assert_cmpuint(magic, ==, 0);
    g_assert_cmpuint(sequence, ==, 0);
    g_assert_cmpuint(poll_count, ==, 0);
    g_assert_cmpuint(last_seq, ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test DMA write detection via polling
 *
 * This simulates a VFIO device writing to the BAR by directly
 * writing to it (which is what the CPU would do). In a real
 * scenario, this would be a DMA write from hardware, but the
 * polling mechanism can't distinguish between CPU and DMA writes.
 */
static void test_dma_write_detection(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar;
    uint32_t poll_count_before, poll_count_after;
    uint32_t last_seq;

    /* Use a fast polling interval for testing (1μs) */
    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-poll-interval=1000");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Read initial poll count */
    poll_count_before = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);

    /* Simulate DMA write: Write magic and sequence number */
    qpci_io_writel(dev, bar, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);
    qpci_io_writel(dev, bar, DMA_BAR_SEQ_OFFSET, 1);

    /*
     * Wait for polling to detect the write
     * Poll interval is 1μs, wait 10ms to be safe
     */
    qtest_clock_step(qts, 10000000); /* 10ms in nanoseconds */

    /* Check that QEMU detected the write */
    poll_count_after = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);
    last_seq = qpci_io_readl(dev, bar, DMA_BAR_LAST_SEQ_OFFSET);

    /* Poll count should have incremented */
    g_assert_cmpuint(poll_count_after, >, poll_count_before);

    /* Last sequence should match what we wrote */
    g_assert_cmpuint(last_seq, ==, 1);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test multiple sequential DMA writes
 */
static void test_multiple_dma_writes(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar;
    uint32_t poll_count_initial, poll_count_current;
    uint32_t last_seq;
    int i;
    const int num_writes = 5;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-poll-interval=1000");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    /* Write magic once */
    qpci_io_writel(dev, bar, DMA_BAR_MAGIC_OFFSET, DMA_BAR_MAGIC_VALUE);

    poll_count_initial = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);

    /* Write multiple sequence numbers */
    for (i = 1; i <= num_writes; i++) {
        qpci_io_writel(dev, bar, DMA_BAR_SEQ_OFFSET, i);
        qtest_clock_step(qts, 10000000); /* 10ms */

        poll_count_current = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);
        last_seq = qpci_io_readl(dev, bar, DMA_BAR_LAST_SEQ_OFFSET);

        /* Each write should be detected */
        g_assert_cmpuint(poll_count_current, >=, poll_count_initial + i);
        g_assert_cmpuint(last_seq, ==, i);
    }

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test that writes without magic value are ignored
 */
static void test_invalid_magic(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    QPCIBar bar;
    uint32_t poll_count_before, poll_count_after;
    uint32_t last_seq;

    qts = qtest_init("-device pci-testdev,addr=04.0,dma-bar-size=4096,"
                     "dma-poll-interval=1000");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    bar = qpci_iomap(dev, DMA_BAR_NUM, NULL);

    poll_count_before = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);

    /* Write sequence number without valid magic */
    qpci_io_writel(dev, bar, DMA_BAR_MAGIC_OFFSET, 0xBADBAD);
    qpci_io_writel(dev, bar, DMA_BAR_SEQ_OFFSET, 1);

    qtest_clock_step(qts, 10000000); /* 10ms */

    poll_count_after = qpci_io_readl(dev, bar, DMA_BAR_POLL_CNT_OFFSET);
    last_seq = qpci_io_readl(dev, bar, DMA_BAR_LAST_SEQ_OFFSET);

    /* Poll count should not have changed */
    g_assert_cmpuint(poll_count_after, ==, poll_count_before);
    /* Last sequence should still be 0 */
    g_assert_cmpuint(last_seq, ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test device without DMA BAR (dma-bar-size=0)
 */
static void test_no_dma_bar(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint32_t bar_addr;

    /* Don't specify dma-bar-size, so BAR 3 should not exist */
    qts = qtest_init("-device pci-testdev,addr=04.0");
    pcibus = qpci_new_pc(qts, NULL);

    dev = qpci_device_find(pcibus, QPCI_DEVFN(TESTDEV_PCI_SLOT, 0));
    g_assert_nonnull(dev);
    qpci_device_enable(dev);

    /* BAR 3 should not be allocated */
    bar_addr = qpci_config_readl(dev, PCI_BASE_ADDRESS_3);
    g_assert_cmpuint(bar_addr, ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/pci-testdev-dma/init", test_dma_bar_init);
    qtest_add_func("/pci-testdev-dma/write-detection",
                   test_dma_write_detection);
    qtest_add_func("/pci-testdev-dma/multiple-writes",
                   test_multiple_dma_writes);
    qtest_add_func("/pci-testdev-dma/invalid-magic", test_invalid_magic);
    qtest_add_func("/pci-testdev-dma/no-dma-bar", test_no_dma_bar);

    return g_test_run();
}

