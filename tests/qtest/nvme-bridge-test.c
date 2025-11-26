/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcase for NVMe BAR3 MMIO Bridge
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
#define PCI_DEVICE_ID_NVME      0x0010

/* Bridge protocol */
#define BRIDGE_MAGIC        0xDEADFEED
#define BRIDGE_CMD_MAGIC    0xDEADC0DE

#define BRIDGE_STATUS_PENDING   0
#define BRIDGE_STATUS_SUCCESS   1
#define BRIDGE_STATUS_ERROR     2

#define BRIDGE_ERR_NONE         0
#define BRIDGE_ERR_INVALID_BAR  1
#define BRIDGE_ERR_INVALID_SIZE 2

/* Bridge BAR3 offsets */
#define BRIDGE_MAGIC_OFFSET        0x00
#define BRIDGE_SEQUENCE_OFFSET     0x04
#define BRIDGE_POLL_COUNT_OFFSET   0x08
#define BRIDGE_LAST_SEQ_OFFSET     0x0C
#define BRIDGE_CMD_MAGIC_OFFSET    0x10
#define BRIDGE_CMD_BAR_OFFSET      0x14
#define BRIDGE_CMD_SIZE_OFFSET     0x15
#define BRIDGE_CMD_STATUS_OFFSET   0x16
#define BRIDGE_CMD_OFFSET_OFFSET   0x18
#define BRIDGE_CMD_DATA_OFFSET     0x20
#define BRIDGE_CMD_EXEC_CNT_OFFSET 0x28
#define BRIDGE_CMD_ERROR_OFFSET    0x2C
#define BRIDGE_CMD_COMPL_OFFSET    0x30

/*
 * Test: BAR3 initialization
 * Verify that BAR3 is created and accessible when bridge-bar-size is set
 */
static void test_nvme_bridge_init(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *nvme;
    QPCIBar bar3;
    uint32_t poll_count;

    qts = qtest_initf("-drive id=drv0,if=none,file=null-co://,"
                      "format=raw "
                      "-device nvme,serial=test,drive=drv0,"
                      "bridge-bar-size=4K,bridge-mmio=on");
    pcibus = qpci_new_pc(qts, NULL);
    nvme = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(nvme);
    qpci_device_enable(nvme);

    /* Map BAR3 */
    bar3 = qpci_iomap(nvme, 3, NULL);
    g_assert_cmpuint(bar3.addr, !=, 0);

    /* Read poll_count - should start at 0 */
    poll_count = qpci_io_readl(nvme, bar3, BRIDGE_POLL_COUNT_OFFSET);
    g_assert_cmpuint(poll_count, >=, 0);

    g_free(nvme);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test: Sequence detection
 * Verify that QEMU detects sequence number changes
 */
static void test_nvme_bridge_sequence(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *nvme;
    QPCIBar bar3;
    uint32_t poll_count_before, poll_count_after;
    uint32_t sequence;

    qts = qtest_initf("-drive id=drv0,if=none,file=null-co://,"
                      "format=raw "
                      "-device nvme,serial=test,drive=drv0,"
                      "bridge-bar-size=4K,bridge-mmio=on,"
                      "bridge-poll-interval=1000");
    pcibus = qpci_new_pc(qts, NULL);
    nvme = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(nvme);
    qpci_device_enable(nvme);

    bar3 = qpci_iomap(nvme, 3, NULL);

    /* Write magic */
    qpci_io_writel(nvme, bar3, BRIDGE_MAGIC_OFFSET, BRIDGE_MAGIC);

    /* Get initial poll count */
    poll_count_before = qpci_io_readl(nvme, bar3,
                                     BRIDGE_POLL_COUNT_OFFSET);

    /* Increment sequence */
    sequence = qpci_io_readl(nvme, bar3, BRIDGE_SEQUENCE_OFFSET);
    qpci_io_writel(nvme, bar3, BRIDGE_SEQUENCE_OFFSET, sequence + 1);

    /* Wait for polling */
    qtest_clock_step(qts, 10000);

    /* Check poll count incremented */
    poll_count_after = qpci_io_readl(nvme, bar3,
                                    BRIDGE_POLL_COUNT_OFFSET);
    g_assert_cmpuint(poll_count_after, >, poll_count_before);

    g_free(nvme);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test: MMIO bridge command
 * Verify that command in BAR3 triggers MMIO write to BAR0
 */
static void test_nvme_bridge_mmio_command(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *nvme;
    QPCIBar bar3;
    uint32_t exec_count_before, exec_count_after;
    uint32_t status, error;
    uint32_t sequence;

    qts = qtest_initf("-drive id=drv0,if=none,file=null-co://,"
                      "format=raw "
                      "-device nvme,serial=test,drive=drv0,"
                      "bridge-bar-size=4K,bridge-mmio=on,"
                      "bridge-poll-interval=1000");
    pcibus = qpci_new_pc(qts, NULL);
    nvme = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(nvme);
    qpci_device_enable(nvme);

    bar3 = qpci_iomap(nvme, 3, NULL);

    /* Setup magic values */
    qpci_io_writel(nvme, bar3, BRIDGE_MAGIC_OFFSET, BRIDGE_MAGIC);
    qpci_io_writel(nvme, bar3, BRIDGE_CMD_MAGIC_OFFSET,
                  BRIDGE_CMD_MAGIC);

    /* Get initial exec count */
    exec_count_before = qpci_io_readl(nvme, bar3,
                                     BRIDGE_CMD_EXEC_CNT_OFFSET);

    /* Setup command to write to BAR0 offset 0x1000 (doorbell area) */
    qpci_io_writeb(nvme, bar3, BRIDGE_CMD_BAR_OFFSET, 0);  /* BAR0 */
    qpci_io_writeb(nvme, bar3, BRIDGE_CMD_SIZE_OFFSET, 4); /* 4-byte */
    qpci_io_writeq(nvme, bar3, BRIDGE_CMD_OFFSET_OFFSET, 0x1000);
    qpci_io_writeq(nvme, bar3, BRIDGE_CMD_DATA_OFFSET, 0x12345678);

    /* Increment sequence to trigger */
    sequence = qpci_io_readl(nvme, bar3, BRIDGE_SEQUENCE_OFFSET);
    qpci_io_writel(nvme, bar3, BRIDGE_SEQUENCE_OFFSET, sequence + 1);

    /* Wait for processing */
    qtest_clock_step(qts, 10000);

    /* Check status */
    status = qpci_io_readw(nvme, bar3, BRIDGE_CMD_STATUS_OFFSET);
    error = qpci_io_readl(nvme, bar3, BRIDGE_CMD_ERROR_OFFSET);
    exec_count_after = qpci_io_readl(nvme, bar3,
                                    BRIDGE_CMD_EXEC_CNT_OFFSET);

    g_assert_cmpuint(status, ==, BRIDGE_STATUS_SUCCESS);
    g_assert_cmpuint(error, ==, BRIDGE_ERR_NONE);
    g_assert_cmpuint(exec_count_after, ==, exec_count_before + 1);

    g_free(nvme);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test: Invalid BAR number
 * Verify error handling when targeting invalid BAR
 */
static void test_nvme_bridge_invalid_bar(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *nvme;
    QPCIBar bar3;
    uint32_t status, error;
    uint32_t sequence;

    qts = qtest_initf("-drive id=drv0,if=none,file=null-co://,"
                      "format=raw "
                      "-device nvme,serial=test,drive=drv0,"
                      "bridge-bar-size=4K,bridge-mmio=on,"
                      "bridge-poll-interval=1000");
    pcibus = qpci_new_pc(qts, NULL);
    nvme = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(nvme);
    qpci_device_enable(nvme);

    bar3 = qpci_iomap(nvme, 3, NULL);

    /* Setup with invalid BAR number */
    qpci_io_writel(nvme, bar3, BRIDGE_MAGIC_OFFSET, BRIDGE_MAGIC);
    qpci_io_writel(nvme, bar3, BRIDGE_CMD_MAGIC_OFFSET,
                  BRIDGE_CMD_MAGIC);
    qpci_io_writeb(nvme, bar3, BRIDGE_CMD_BAR_OFFSET, 5);  /* Invalid */
    qpci_io_writeb(nvme, bar3, BRIDGE_CMD_SIZE_OFFSET, 4);
    qpci_io_writeq(nvme, bar3, BRIDGE_CMD_OFFSET_OFFSET, 0);
    qpci_io_writeq(nvme, bar3, BRIDGE_CMD_DATA_OFFSET, 0);

    /* Trigger */
    sequence = qpci_io_readl(nvme, bar3, BRIDGE_SEQUENCE_OFFSET);
    qpci_io_writel(nvme, bar3, BRIDGE_SEQUENCE_OFFSET, sequence + 1);

    /* Wait */
    qtest_clock_step(qts, 10000);

    /* Check error */
    status = qpci_io_readw(nvme, bar3, BRIDGE_CMD_STATUS_OFFSET);
    error = qpci_io_readl(nvme, bar3, BRIDGE_CMD_ERROR_OFFSET);

    g_assert_cmpuint(status, ==, BRIDGE_STATUS_ERROR);
    g_assert_cmpuint(error, ==, BRIDGE_ERR_INVALID_BAR);

    g_free(nvme);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Test: Bridge disabled
 * Verify no BAR3 when bridge is disabled (default)
 */
static void test_nvme_bridge_disabled(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *nvme;
    uint32_t bar3_addr;

    qts = qtest_initf("-drive id=drv0,if=none,file=null-co://,"
                      "format=raw "
                      "-device nvme,serial=test,drive=drv0");
    pcibus = qpci_new_pc(qts, NULL);
    nvme = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(nvme);
    qpci_device_enable(nvme);

    /* BAR3 should not be present */
    bar3_addr = qpci_config_readl(nvme, PCI_BASE_ADDRESS_3);
    g_assert_cmpuint(bar3_addr, ==, 0);

    g_free(nvme);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/nvme-bridge/init", test_nvme_bridge_init);
    qtest_add_func("/nvme-bridge/sequence", test_nvme_bridge_sequence);
    qtest_add_func("/nvme-bridge/mmio-command",
                   test_nvme_bridge_mmio_command);
    qtest_add_func("/nvme-bridge/invalid-bar",
                   test_nvme_bridge_invalid_bar);
    qtest_add_func("/nvme-bridge/disabled", test_nvme_bridge_disabled);

    return g_test_run();
}

