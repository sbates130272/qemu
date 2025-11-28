/*
 * QTest testcases for PCI MMIO Bridge (PCI Device)
 *
 * Copyright (c) 2024 Your Name
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "qemu/module.h"
#include "hw/pci/pci_ids.h"
#include "hw/pci/pci_regs.h"

/* PCI IDs for the bridge device */
#define PCI_VENDOR_ID_REDHAT_QEMU  0x1b36
#define PCI_DEVICE_ID_MMIO_BRIDGE  0x0010

/* Vendor-specific config space offsets */
#define PCI_MMIO_BRIDGE_CAP_OFFSET  0x40
#define PCI_MMIO_BRIDGE_CAP_GPA_LO  0x00
#define PCI_MMIO_BRIDGE_CAP_GPA_HI  0x04
#define PCI_MMIO_BRIDGE_CAP_SIZE    0x08
#define PCI_MMIO_BRIDGE_CAP_DEPTH   0x0C

/* Helper: Read shadow buffer GPA from PCI config space */
static uint64_t read_shadow_gpa(QPCIDevice *dev)
{
    uint32_t gpa_lo = qpci_config_readl(dev, PCI_MMIO_BRIDGE_CAP_OFFSET + 
                                        PCI_MMIO_BRIDGE_CAP_GPA_LO);
    uint32_t gpa_hi = qpci_config_readl(dev, PCI_MMIO_BRIDGE_CAP_OFFSET + 
                                        PCI_MMIO_BRIDGE_CAP_GPA_HI);
    return ((uint64_t)gpa_hi << 32) | gpa_lo;
}

/* Helper: Read shadow buffer size from PCI config space */
static uint32_t read_shadow_size(QPCIDevice *dev)
{
    return qpci_config_readl(dev, PCI_MMIO_BRIDGE_CAP_OFFSET + 
                            PCI_MMIO_BRIDGE_CAP_SIZE);
}

/* Helper: Read queue depth from PCI config space */
static uint32_t read_queue_depth(QPCIDevice *dev)
{
    return qpci_config_readl(dev, PCI_MMIO_BRIDGE_CAP_OFFSET + 
                            PCI_MMIO_BRIDGE_CAP_DEPTH);
}

/* Helper: Find bridge device on PCI bus */
static QPCIDevice *find_pci_mmio_bridge(QPCIBus *bus)
{
    for (int devfn = 0; devfn < 256; devfn++) {
        QPCIDevice *dev = qpci_device_find(bus, devfn);
        if (dev) {
            uint16_t vid = qpci_config_readw(dev, PCI_VENDOR_ID);
            uint16_t did = qpci_config_readw(dev, PCI_DEVICE_ID);
            if (vid == PCI_VENDOR_ID_REDHAT_QEMU && 
                did == PCI_DEVICE_ID_MMIO_BRIDGE) {
                return dev;
            }
            g_free(dev);
        }
    }
    return NULL;
}

/* Helper: Find pci-testdev on PCI bus */
static QPCIDevice *find_pci_testdev(QPCIBus *bus)
{
    for (int devfn = 0; devfn < 256; devfn++) {
        QPCIDevice *dev = qpci_device_find(bus, devfn);
        if (dev) {
            uint16_t did = qpci_config_readw(dev, PCI_DEVICE_ID);
            if (did == 0x5050) {  /* pci-testdev device ID */
                return dev;
            }
            g_free(dev);
        }
    }
    return NULL;
}

/* Command packet structure (must match hw/pci/pci-mmio-bridge.h) */
struct pci_mmio_command {
    uint16_t target_bdf;
    uint8_t  target_bar;
    uint8_t  reserved1;
    uint32_t offset;
    uint64_t value;
    uint8_t  command;
    uint8_t  size;
    uint8_t  status;
    uint8_t  reserved2;
    uint32_t sequence;
} QEMU_PACKED;

/* Ring buffer metadata */
struct pci_mmio_ring_meta {
    uint32_t producer_idx;
    uint32_t consumer_idx;
    uint32_t queue_depth;
    uint32_t reserved;
} QEMU_PACKED;

/* Command types */
#define PCI_MMIO_CMD_NOP    0
#define PCI_MMIO_CMD_WRITE  1
#define PCI_MMIO_CMD_READ   2

/* Status codes */
#define PCI_MMIO_STATUS_PENDING   0
#define PCI_MMIO_STATUS_COMPLETE  1
#define PCI_MMIO_STATUS_ERROR     2

/* Test: Device discovery via PCI bus enumeration */
static void test_pci_device_discovery(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint16_t vendor_id, device_id;
    uint8_t class_id;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0");

    pcibus = qpci_new_pc(qts, NULL);
    g_assert_nonnull(pcibus);

    /* Find the bridge device */
    dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(dev);

    /* Verify PCI IDs */
    vendor_id = qpci_config_readw(dev, PCI_VENDOR_ID);
    device_id = qpci_config_readw(dev, PCI_DEVICE_ID);
    class_id = qpci_config_readb(dev, PCI_CLASS_DEVICE);

    g_assert_cmpuint(vendor_id, ==, PCI_VENDOR_ID_REDHAT_QEMU);
    g_assert_cmpuint(device_id, ==, PCI_DEVICE_ID_MMIO_BRIDGE);
    g_assert_cmpuint(class_id, ==, 0x80); /* PCI_CLASS_SYSTEM_OTHER */

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: Shadow buffer GPA is exposed via config space */
static void test_pci_shadow_gpa_access(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint64_t shadow_gpa;
    uint32_t shadow_size, queue_depth;
    struct pci_mmio_ring_meta meta;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0,shadow-size=4096");

    pcibus = qpci_new_pc(qts, NULL);
    dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(dev);

    /* Enable device */
    qpci_device_enable(dev);

    /* Read shadow buffer location from PCI config space */
    shadow_gpa = read_shadow_gpa(dev);
    shadow_size = read_shadow_size(dev);
    queue_depth = read_queue_depth(dev);

    /* Verify config space values */
    g_assert_cmpuint(shadow_gpa, >, 0);
    g_assert_cmpuint(shadow_size, ==, 4096);
    g_assert_cmpuint(queue_depth, ==, 169);  /* (4096/24)-1 */

    /* Read ring metadata from guest RAM at shadow_gpa */
    qtest_memread(qts, shadow_gpa, &meta, sizeof(meta));

    /* Verify metadata is initialized */
    g_assert_cmpuint(meta.producer_idx, ==, 0);
    g_assert_cmpuint(meta.consumer_idx, ==, 0);
    g_assert_cmpuint(meta.queue_depth, ==, 169);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: Shadow size property */
static void test_pci_shadow_size_property(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint64_t shadow_gpa;
    uint32_t shadow_size, queue_depth;
    struct pci_mmio_ring_meta meta;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,shadow-size=8192");

    pcibus = qpci_new_pc(qts, NULL);
    dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(dev);

    qpci_device_enable(dev);

    /* Read shadow buffer info from config space */
    shadow_gpa = read_shadow_gpa(dev);
    shadow_size = read_shadow_size(dev);
    queue_depth = read_queue_depth(dev);
    
    /* Verify size is 8192 and queue depth matches: (8192/24)-1 = 340 */
    g_assert_cmpuint(shadow_size, ==, 8192);
    g_assert_cmpuint(queue_depth, ==, 340);

    /* Verify metadata in guest RAM */
    qtest_memread(qts, shadow_gpa, &meta, sizeof(meta));
    g_assert_cmpuint(meta.queue_depth, ==, 340);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: Basic write command via shadow buffer */
static void test_pci_write_command(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *bridge_dev, *test_dev;
    QPCIBar test_bar;
    uint64_t shadow_gpa;
    struct pci_mmio_command cmd = {0};
    struct pci_mmio_ring_meta meta;
    uint32_t test_value_read;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0 "
                     "-device pci-testdev,id=testdev0");

    pcibus = qpci_new_pc(qts, NULL);
    
    /* Get bridge device and shadow GPA */
    bridge_dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(bridge_dev);
    qpci_device_enable(bridge_dev);
    shadow_gpa = read_shadow_gpa(bridge_dev);

    /* Get test device */
    test_dev = find_pci_testdev(pcibus);
    if (!test_dev) {
        g_test_skip("pci-testdev not available");
        g_free(bridge_dev);
        qpci_free_pc(pcibus);
        qtest_quit(qts);
        return;
    }
    qpci_device_enable(test_dev);
    test_bar = qpci_iomap(test_dev, 0, NULL);

    /* Prepare write command */
    cmd.target_bdf = (0 << 8) | test_dev->devfn;
    cmd.target_bar = 0;
    cmd.offset = 0;
    cmd.value = 0xDEADBEEF;
    cmd.command = PCI_MMIO_CMD_WRITE;
    cmd.size = 4;
    cmd.status = PCI_MMIO_STATUS_PENDING;
    cmd.sequence = 1;

    /* Write command to slot 1 in guest RAM (slot 0 is metadata) */
    qtest_memwrite(qts, shadow_gpa + sizeof(meta), &cmd, sizeof(cmd));

    /* Update producer index to signal command */
    meta.producer_idx = 1;
    qtest_memwrite(qts, shadow_gpa, &meta.producer_idx, 4);

    /* Give QEMU time to process (BH should trigger) */
    qtest_clock_step(qts, 10000000); /* 10ms */

    /* Read back command to check status */
    qtest_memread(qts, shadow_gpa + sizeof(meta), &cmd, sizeof(cmd));
    g_assert_cmpuint(cmd.status, ==, PCI_MMIO_STATUS_COMPLETE);

    /* Verify write reached target device */
    test_value_read = qpci_io_readl(test_dev, test_bar, 0);
    g_assert_cmpuint(test_value_read, ==, 0xDEADBEEF);

    g_free(bridge_dev);
    g_free(test_dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: Basic read command via shadow buffer */
static void test_pci_read_command(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *bridge_dev, *test_dev;
    QPCIBar test_bar;
    uint64_t shadow_gpa;
    struct pci_mmio_command cmd = {0};
    struct pci_mmio_ring_meta meta;
    uint32_t expected_value = 0xCAFEBABE;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0 "
                     "-device pci-testdev,id=testdev0");

    pcibus = qpci_new_pc(qts, NULL);
    
    bridge_dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(bridge_dev);
    qpci_device_enable(bridge_dev);
    shadow_gpa = read_shadow_gpa(bridge_dev);

    test_dev = find_pci_testdev(pcibus);
    if (!test_dev) {
        g_test_skip("pci-testdev not available");
        g_free(bridge_dev);
        qpci_free_pc(pcibus);
        qtest_quit(qts);
        return;
    }
    qpci_device_enable(test_dev);
    test_bar = qpci_iomap(test_dev, 0, NULL);

    /* Write a value to test device first */
    qpci_io_writel(test_dev, test_bar, 0, expected_value);

    /* Prepare read command */
    cmd.target_bdf = (0 << 8) | test_dev->devfn;
    cmd.target_bar = 0;
    cmd.offset = 0;
    cmd.value = 0;
    cmd.command = PCI_MMIO_CMD_READ;
    cmd.size = 4;
    cmd.status = PCI_MMIO_STATUS_PENDING;
    cmd.sequence = 1;

    /* Write command to slot 1 in guest RAM */
    qtest_memwrite(qts, shadow_gpa + sizeof(meta), &cmd, sizeof(cmd));

    /* Signal command */
    meta.producer_idx = 1;
    qtest_memwrite(qts, shadow_gpa, &meta.producer_idx, 4);

    /* Wait for processing */
    qtest_clock_step(qts, 10000000);

    /* Read back command */
    qtest_memread(qts, shadow_gpa + sizeof(meta), &cmd, sizeof(cmd));
    g_assert_cmpuint(cmd.status, ==, PCI_MMIO_STATUS_COMPLETE);
    g_assert_cmpuint(cmd.value, ==, expected_value);

    g_free(bridge_dev);
    g_free(test_dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: Device reset clears statistics */
static void test_pci_device_reset(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev;
    uint64_t shadow_gpa;
    struct pci_mmio_ring_meta meta;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0");

    pcibus = qpci_new_pc(qts, NULL);
    dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(dev);

    qpci_device_enable(dev);
    shadow_gpa = read_shadow_gpa(dev);

    /* Write some data to producer index */
    meta.producer_idx = 5;
    qtest_memwrite(qts, shadow_gpa, &meta.producer_idx, 4);

    /* Reset device */
    qtest_qmp_send(qts, "{ 'execute': 'system_reset' }");
    qtest_qmp_receive(qts);
    qtest_clock_step(qts, 1000000);

    /* Verify producer index reset to 0 */
    qtest_memread(qts, shadow_gpa, &meta, sizeof(meta));
    g_assert_cmpuint(meta.producer_idx, ==, 0);
    g_assert_cmpuint(meta.consumer_idx, ==, 0);

    g_free(dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/* Test: Multiple bridges can coexist */
static void test_pci_multiple_bridges(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *dev1, *dev2;
    uint16_t device_id;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0,addr=4.0 "
                     "-device pci-mmio-bridge,id=bridge1,addr=5.0");

    pcibus = qpci_new_pc(qts, NULL);
    
    /* Find first bridge */
    dev1 = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(dev1);
    device_id = qpci_config_readw(dev1, PCI_DEVICE_ID);
    g_assert_cmpuint(device_id, ==, PCI_DEVICE_ID_MMIO_BRIDGE);

    /* Find second bridge */
    dev2 = qpci_device_find(pcibus, QPCI_DEVFN(5, 0));
    g_assert_nonnull(dev2);
    device_id = qpci_config_readw(dev2, PCI_DEVICE_ID);
    g_assert_cmpuint(device_id, ==, PCI_DEVICE_ID_MMIO_BRIDGE);

    g_free(dev1);
    g_free(dev2);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    qtest_add_func("/pci-mmio-bridge-pci/device-discovery",
                   test_pci_device_discovery);
    qtest_add_func("/pci-mmio-bridge-pci/shadow-gpa-access",
                   test_pci_shadow_gpa_access);
    qtest_add_func("/pci-mmio-bridge-pci/shadow-size-property",
                   test_pci_shadow_size_property);
    qtest_add_func("/pci-mmio-bridge-pci/write-command",
                   test_pci_write_command);
    qtest_add_func("/pci-mmio-bridge-pci/read-command",
                   test_pci_read_command);
    qtest_add_func("/pci-mmio-bridge-pci/device-reset",
                   test_pci_device_reset);
    qtest_add_func("/pci-mmio-bridge-pci/multiple-bridges",
                   test_pci_multiple_bridges);

    return g_test_run();
}

