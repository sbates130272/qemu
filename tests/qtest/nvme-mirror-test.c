/*
 * QTest testcases for NVMe PCI BAR Mirror
 *
 * Copyright (c) 2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This test suite validates the PCI BAR mirror infrastructure
 * when used with the NVMe device.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "qemu/module.h"
#include "qemu/bitops.h"
#include "standard-headers/linux/pci_regs.h"

/* Test: NVMe device initializes with mirror enabled */
static void test_nvme_mirror_enabled(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint16_t vendor_id, device_id;

    qts = qtest_initf("-machine q35 "
                      "-drive id=drv0,if=none,file=null-co://,format=raw "
                      "-device nvme,addr=04.0,serial=test,drive=drv0,"
                      "mirror-enabled=on,mirror-size=4096");

    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(dev);

    /* Verify NVMe device is present and responding */
    vendor_id = qpci_config_readw(dev, PCI_VENDOR_ID);
    device_id = qpci_config_readw(dev, PCI_DEVICE_ID);

    /* NVMe should have Red Hat vendor ID (default) */
    g_assert_cmphex(vendor_id, ==, 0x1b36);
    g_assert_cmphex(device_id, ==, 0x0010);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: NVMe device initializes with mirror disabled */
static void test_nvme_mirror_disabled(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint16_t vendor_id;

    qts = qtest_initf("-machine q35 "
                      "-drive id=drv0,if=none,file=null-co://,format=raw "
                      "-device nvme,addr=04.0,serial=test,drive=drv0");

    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(dev);

    /* Verify device is present */
    vendor_id = qpci_config_readw(dev, PCI_VENDOR_ID);
    g_assert_cmphex(vendor_id, ==, 0x1b36);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: NVMe with custom mirror properties */
static void test_nvme_mirror_properties(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint16_t vendor_id;

    /* Test with custom mirror configuration */
    qts = qtest_initf("-machine q35 "
                      "-drive id=drv0,if=none,file=null-co://,format=raw "
                      "-device nvme,addr=04.0,serial=test,drive=drv0,"
                      "mirror-enabled=on,mirror-size=2048,"
                      "mirror-target-bar=0,mirror-target-offset=0");

    pcibus = qpci_new_pc(qts, NULL);
    dev = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(dev);

    /* Verify device initializes with custom properties */
    vendor_id = qpci_config_readw(dev, PCI_VENDOR_ID);
    g_assert_cmphex(vendor_id, ==, 0x1b36);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/x86_64/nvme-mirror/enabled",
                   test_nvme_mirror_enabled);
    qtest_add_func("/x86_64/nvme-mirror/disabled",
                   test_nvme_mirror_disabled);
    qtest_add_func("/x86_64/nvme-mirror/properties",
                   test_nvme_mirror_properties);

    return g_test_run();
}

