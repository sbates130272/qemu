/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QTest testcases for PCI MMIO Bridge (PCI Device)
 *
 * Copyright (c) 2025 Stephen Bates <sbates@raithlin.com>
 */

#include "qemu/osdep.h"
#include "libqtest.h"
#include "libqos/pci.h"
#include "libqos/pci-pc.h"
#include "hw/pci/pci_regs.h"
#include "hw/pci/pci-mmio-bridge.h"

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
            if (vid == PCI_VENDOR_ID_REDHAT &&
                did == PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE) {
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

    g_assert_cmpuint(vendor_id, ==, PCI_VENDOR_ID_REDHAT);
    g_assert_cmpuint(device_id, ==, PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE);
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
    struct pci_mmio_bridge_ring_meta meta;

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
    struct pci_mmio_bridge_ring_meta meta;

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
    struct pci_mmio_bridge_command cmd = {0};
    struct pci_mmio_bridge_ring_meta meta;
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
    cmd.command = PCI_MMIO_BRIDGE_CMD_WRITE;
    cmd.size = 4;
    cmd.status = PCI_MMIO_BRIDGE_STATUS_PENDING;
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
    g_assert_cmpuint(cmd.status, ==, PCI_MMIO_BRIDGE_STATUS_COMPLETE);

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
    struct pci_mmio_bridge_command cmd = {0};
    struct pci_mmio_bridge_ring_meta meta;
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
    cmd.command = PCI_MMIO_BRIDGE_CMD_READ;
    cmd.size = 4;
    cmd.status = PCI_MMIO_BRIDGE_STATUS_PENDING;
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
    g_assert_cmpuint(cmd.status, ==, PCI_MMIO_BRIDGE_STATUS_COMPLETE);
    g_assert_cmpuint(cmd.value, ==, expected_value);

    g_free(bridge_dev);
    g_free(test_dev);
    qpci_free_pc(pcibus);
    qtest_quit(qts);
}

/*
 * Raw PCI config space accessors with explicit bus number.
 *
 * The qtest QPCIBus helpers hard-code bus 0. These use the x86 CF8/CFC
 * mechanism directly, encoding the bus number in the address word so we
 * can reach devices behind root ports on secondary buses.
 */
static uint32_t raw_pci_cfg_addr(uint8_t bus, uint8_t devfn, uint8_t off)
{
    return (1U << 31) | ((uint32_t)bus << 16) |
           ((uint32_t)devfn << 8) | (off & 0xFC);
}

static uint16_t raw_pci_config_readw(QTestState *qts,
                                     uint8_t bus, uint8_t devfn, uint8_t off)
{
    qtest_outl(qts, 0xcf8, raw_pci_cfg_addr(bus, devfn, off));
    return qtest_inw(qts, 0xcfc + (off & 2));
}

static void raw_pci_config_writew(QTestState *qts,
                                  uint8_t bus, uint8_t devfn,
                                  uint8_t off, uint16_t val)
{
    qtest_outl(qts, 0xcf8, raw_pci_cfg_addr(bus, devfn, off));
    qtest_outw(qts, 0xcfc + (off & 2), val);
}

static uint32_t raw_pci_config_readl(QTestState *qts,
                                     uint8_t bus, uint8_t devfn, uint8_t off)
{
    qtest_outl(qts, 0xcf8, raw_pci_cfg_addr(bus, devfn, off));
    return qtest_inl(qts, 0xcfc);
}

static void raw_pci_config_writel(QTestState *qts,
                                  uint8_t bus, uint8_t devfn,
                                  uint8_t off, uint32_t val)
{
    qtest_outl(qts, 0xcf8, raw_pci_cfg_addr(bus, devfn, off));
    qtest_outl(qts, 0xcfc, val);
}

/* Test: Write command targeting a device on a secondary (non-zero) PCI bus */
static void test_pci_write_command_secondary_bus(void)
{
    QTestState *qts;
    QPCIBus *pcibus;
    QPCIDevice *bridge_dev, *rp_dev;
    uint64_t shadow_gpa;
    struct pci_mmio_bridge_command cmd = {0};
    struct pci_mmio_bridge_ring_meta meta;
    uint16_t target_bdf, vid;
    const uint8_t sec_bus = 1;
    const uint8_t testdev_devfn = 0;
    const uint32_t bar_addr = 0xF0000000;

    qts = qtest_init("-machine q35 "
                     "-device pci-mmio-bridge,id=bridge0 "
                     "-device pcie-root-port,id=rp0,bus=pcie.0,"
                     "addr=4.0,chassis=1 "
                     "-device pci-testdev,id=testdev0,bus=rp0");

    pcibus = qpci_new_pc(qts, NULL);

    bridge_dev = find_pci_mmio_bridge(pcibus);
    g_assert_nonnull(bridge_dev);
    qpci_device_enable(bridge_dev);
    shadow_gpa = read_shadow_gpa(bridge_dev);

    /*
     * Program the root port (bus 0, devfn 0x20 = device 4) so that
     * its secondary bus number is assigned and its memory window is
     * open.  Without firmware, qtest must do this manually.
     */
    rp_dev = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(rp_dev);

    qpci_config_writeb(rp_dev, PCI_PRIMARY_BUS, 0);
    qpci_config_writeb(rp_dev, PCI_SECONDARY_BUS, sec_bus);
    qpci_config_writeb(rp_dev, PCI_SUBORDINATE_BUS, sec_bus);

    /* Memory window: 0xF000_0000 – 0xF00F_FFFF (1 MB) */
    qpci_config_writew(rp_dev, PCI_MEMORY_BASE,
                       (bar_addr >> 16) & 0xFFF0);
    qpci_config_writew(rp_dev, PCI_MEMORY_LIMIT,
                       (bar_addr >> 16) & 0xFFF0);

    /* Enable memory space + bus master on the root port */
    qpci_config_writew(rp_dev, PCI_COMMAND,
                       PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

    /*
     * Now we can reach the pci-testdev on bus 1 via CF8/CFC with the
     * bus number encoded in the config address.
     */
    vid = raw_pci_config_readw(qts, sec_bus, testdev_devfn, PCI_VENDOR_ID);
    if (vid == 0xFFFF) {
        g_test_skip("pci-testdev not visible on secondary bus");
        g_free(bridge_dev);
        g_free(rp_dev);
        qpci_free_pc(pcibus);
        qtest_quit(qts);
        return;
    }

    /* Assign BAR 0 and enable memory decoding on the test device */
    raw_pci_config_writel(qts, sec_bus, testdev_devfn,
                          PCI_BASE_ADDRESS_0, bar_addr);
    raw_pci_config_writew(qts, sec_bus, testdev_devfn,
                          PCI_COMMAND,
                          PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);

    /* Confirm BAR was programmed */
    g_assert_cmphex(raw_pci_config_readl(qts, sec_bus, testdev_devfn,
                                         PCI_BASE_ADDRESS_0) & ~0xF,
                    ==, bar_addr);

    target_bdf = ((uint16_t)sec_bus << 8) | testdev_devfn;

    /* Write command targeting the secondary-bus device */
    cmd.target_bdf = target_bdf;
    cmd.target_bar = 0;
    cmd.offset = 0;
    cmd.value = 0xBEEFCAFE;
    cmd.command = PCI_MMIO_BRIDGE_CMD_WRITE;
    cmd.size = 4;
    cmd.status = PCI_MMIO_BRIDGE_STATUS_PENDING;
    cmd.sequence = 1;

    qtest_memwrite(qts, shadow_gpa + sizeof(meta), &cmd, sizeof(cmd));

    meta.producer_idx = 1;
    qtest_memwrite(qts, shadow_gpa, &meta.producer_idx, 4);

    qtest_clock_step(qts, 10000000);

    qtest_memread(qts, shadow_gpa + sizeof(meta), &cmd, sizeof(cmd));
    g_assert_cmpuint(cmd.status, ==, PCI_MMIO_BRIDGE_STATUS_COMPLETE);

    g_free(bridge_dev);
    g_free(rp_dev);
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
    struct pci_mmio_bridge_ring_meta meta;

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
                     "-device pci-mmio-bridge,id=bridge0,addr=4.0,"
                     "shadow-gpa=0x80000000 "
                     "-device pci-mmio-bridge,id=bridge1,addr=5.0,"
                     "shadow-gpa=0x81000000");

    pcibus = qpci_new_pc(qts, NULL);

    /* Find first bridge */
    dev1 = qpci_device_find(pcibus, QPCI_DEVFN(4, 0));
    g_assert_nonnull(dev1);
    device_id = qpci_config_readw(dev1, PCI_DEVICE_ID);
    g_assert_cmpuint(device_id, ==, PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE);

    /* Find second bridge */
    dev2 = qpci_device_find(pcibus, QPCI_DEVFN(5, 0));
    g_assert_nonnull(dev2);
    device_id = qpci_config_readw(dev2, PCI_DEVICE_ID);
    g_assert_cmpuint(device_id, ==, PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE);

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
    qtest_add_func("/pci-mmio-bridge-pci/write-command-secondary-bus",
                   test_pci_write_command_secondary_bus);
    qtest_add_func("/pci-mmio-bridge-pci/device-reset",
                   test_pci_device_reset);
    qtest_add_func("/pci-mmio-bridge-pci/multiple-bridges",
                   test_pci_multiple_bridges);

    return g_test_run();
}

