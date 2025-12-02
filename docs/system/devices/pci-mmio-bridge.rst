.. SPDX-License-Identifier: GPL-2.0-or-later

===============
PCI MMIO Bridge
===============

The PCI MMIO Bridge is an emulated PCI device that provides a mechanism for
PCI devices to perform MMIO (Memory-Mapped I/O) operations on other PCI
devices via command packets. This enables software-defined PCIe peer-to-peer
(P2P) communication between any combination of emulated and real PCI devices.

Overview
========

The PCI MMIO Bridge uses a hybrid architecture:

1. **PCI Device**: Provides guest OS discovery via standard enumeration.
2. **Shadow Buffer**: Allocated in guest RAM.
3. **PCI Config Space**: Exposes shadow buffer GPA in vendor-specific
   registers.

VFIO can only map guest RAM not emulated PCI MMIO space. And, at the present
time, VFIO cannot map MMIO space into an IOVA mapping. Therefore the PCI MMIO
Bridge uses a small amount of guest RAM mapped into its Guest Physical Address
(GPA) space.

Command Queue Structure
=======================

The PCI MMIO Bridge uses a ring buffer in guest RAM. The first 24 bytes
of the ring buffer contain metadata. The rest of the ring buffer contains
command slots:

.. code-block:: c

   struct pci_mmio_bridge_ring_meta {
       uint32_t producer_idx;  /* Written by initiator */
       uint32_t consumer_idx;  /* Written by QEMU */
       uint32_t queue_depth;   /* Number of available slots */
       uint32_t reserved[3];
   };

   struct pci_mmio_bridge_command {
       uint16_t target_bdf;    /* Bus:Device:Function */
       uint8_t  target_bar;    /* Which BAR on target */
       uint8_t  reserved1;
       uint32_t offset;        /* Offset within BAR */
       uint32_t value;         /* Write value / read result */
       uint8_t  command;       /* 0=NOP, 1=WRITE, 2=READ */
       uint8_t  size;          /* 1, 2, 4, or 8 bytes */
       uint8_t  status;        /* 0=pending, 1=complete, 2=error */
       uint8_t  reserved2;
       uint32_t sequence;      /* For ordering */
       uint32_t reserved3;
   };

With the default 4KiB shadow buffer size, the queue provides 169 command slots.

Processing Model
================

QEMU polls the command queue periodically (default 1ms interval). When
the producer index differs from the consumer index:

1. QEMU reads pending command(s) from the queue
2. For each command:

   * Locates the target PCI device (emulated or real) by BDF
   * Dispatches MMIO read/write to the target device's BAR
   * Updates the command status field (complete or error)
   * Updates the result value (for reads)

3. Updates the consumer index
4. Reschedules the next poll

Device Configuration
====================

The PCI MMIO Bridge appears as a standard PCI device:

- **Vendor ID**: 0x1b36 (Red Hat/QEMU)
- **Device ID**: 0x0015 (PCI MMIO Bridge)
- **Class**: 0x08/0x80 (System/Other)

Basic Usage
-----------

.. code-block:: console

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=mmio-bridge

This creates a bridge with defaults:

- Shadow GPA: 0x80000000
- Shadow size: 4096 bytes
- Polling interval: 1ms

Custom Configuration
---------------------

.. code-block:: console

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=mmio-bridge,\
               shadow-gpa=0x90000000,\
               shadow-size=8192,\
               poll-interval-ns=500000

Properties:

- ``shadow-gpa``: Guest physical address for buffer (0 = auto, default:
  0x80000000)
- ``shadow-size``: Buffer size in bytes (default: 4096, min: 4096)
- ``poll-interval-ns``: Polling interval in nanoseconds (default:
  1000000)
- ``enabled``: Enable/disable bridge (default: true)
- ``addr``: PCI slot address (e.g., ``addr=5.0`` for slot 5)

Guest Software Interface
========================

Guest drivers can read the vendor-specific config space to find the GPA of
the shadow buffer:

.. code-block:: c

   #define PCI_MMIO_BRIDGE_CAP_OFFSET  0x40
   #define PCI_MMIO_BRIDGE_CAP_GPA_LO  0x00
   #define PCI_MMIO_BRIDGE_CAP_GPA_HI  0x04
   #define PCI_MMIO_BRIDGE_CAP_SIZE    0x08
   #define PCI_MMIO_BRIDGE_CAP_DEPTH   0x0C

   /* Read shadow buffer GPA */
   uint32_t gpa_lo = pci_read_config_dword(pdev,
                                          PCI_MMIO_BRIDGE_CAP_OFFSET + 0);
   uint32_t gpa_hi = pci_read_config_dword(pdev,
                                          PCI_MMIO_BRIDGE_CAP_OFFSET + 4);
   uint64_t shadow_gpa = ((uint64_t)gpa_hi << 32) | gpa_lo;

   /* Read buffer size and queue depth */
   uint32_t shadow_size = pci_read_config_dword(pdev,
                                                PCI_MMIO_BRIDGE_CAP_OFFSET + 8);
   uint32_t queue_depth = pci_read_config_dword(pdev,
                                                PCI_MMIO_BRIDGE_CAP_OFFSET + 12);

Linux Kernel Driver Example
---------------------------

Example PCI driver that discovers and uses the bridge:

.. code-block:: c

   #include <linux/pci.h>
   #include <linux/module.h>
   #include <linux/io.h>

   #define PCI_VENDOR_ID_REDHAT_QEMU  0x1b36
   #define PCI_DEVICE_ID_REDHAT_MMIO_BRIDGE  0x0015

   /* Config space offsets */
   #define CAP_OFFSET  0x40
   #define CAP_GPA_LO  0x00
   #define CAP_GPA_HI  0x04
   #define CAP_SIZE    0x08
   #define CAP_DEPTH   0x0C

   struct mmio_bridge_dev {
       struct pci_dev *pdev;
       void __iomem *shadow_buf;
       uint64_t shadow_gpa;
       uint32_t shadow_size;
       uint32_t queue_depth;
   };

   static int mmio_bridge_probe(struct pci_dev *pdev,
                                const struct pci_device_id *id)
   {
       struct mmio_bridge_dev *dev;
       uint32_t gpa_lo, gpa_hi;
       int err;

       dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
       if (!dev)
           return -ENOMEM;

       dev->pdev = pdev;

       err = pci_enable_device(pdev);
       if (err)
           return err;

       /* Read shadow buffer location from config space */
       pci_read_config_dword(pdev, CAP_OFFSET + CAP_GPA_LO, &gpa_lo);
       pci_read_config_dword(pdev, CAP_OFFSET + CAP_GPA_HI, &gpa_hi);
       pci_read_config_dword(pdev, CAP_OFFSET + CAP_SIZE, &dev->shadow_size);
       pci_read_config_dword(pdev, CAP_OFFSET + CAP_DEPTH, &dev->queue_depth);

       dev->shadow_gpa = ((uint64_t)gpa_hi << 32) | gpa_lo;

       pr_info("PCI MMIO Bridge: GPA=0x%llx size=%u depth=%u\n",
               dev->shadow_gpa, dev->shadow_size, dev->queue_depth);

       /* Map shadow buffer (guest RAM, not MMIO) */
       dev->shadow_buf = ioremap(dev->shadow_gpa, dev->shadow_size);
       if (!dev->shadow_buf) {
           err = -ENOMEM;
           goto err_disable;
       }

       pci_set_drvdata(pdev, dev);

       return 0;

   err_disable:
       pci_disable_device(pdev);
       return err;
   }

   static void mmio_bridge_remove(struct pci_dev *pdev)
   {
       struct mmio_bridge_dev *dev = pci_get_drvdata(pdev);

       if (dev->shadow_buf)
           iounmap(dev->shadow_buf);

       pci_disable_device(pdev);
   }

   static const struct pci_device_id mmio_bridge_ids[] = {
       { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QEMU,
                    PCI_DEVICE_ID_MMIO_BRIDGE) },
       { 0, }
   };
   MODULE_DEVICE_TABLE(pci, mmio_bridge_ids);

   static struct pci_driver mmio_bridge_driver = {
       .name       = "pci-mmio-bridge",
       .id_table   = mmio_bridge_ids,
       .probe      = mmio_bridge_probe,
       .remove     = mmio_bridge_remove,
   };

   module_pci_driver(mmio_bridge_driver);
   MODULE_LICENSE("GPL");

Submitting Commands
-------------------

Example code for writing to a PCI device's BAR:

.. code-block:: c

   #include <linux/io.h>

   volatile struct pci_mmio_bridge_ring_meta *meta;
   volatile struct pci_mmio_bridge_command *cmds;

   void init_bridge(void __iomem *shadow_buf)
   {
       meta = (struct pci_mmio_bridge_ring_meta *)shadow_buf;
       cmds = (struct pci_mmio_bridge_command *)(shadow_buf +
                                          sizeof(*meta));

       /* Verify queue is initialized */
       if (meta->queue_depth == 0) {
           pr_err("PCI MMIO bridge not available\n");
           return;
       }
       pr_info("Bridge ready: %u slots\n",
               meta->queue_depth);
   }

   int pci_mmio_write_bar(u16 bdf, u8 bar, u32 offset,
                          u32 value, u8 size)
   {
       u32 slot = meta->producer_idx % meta->queue_depth;
       struct pci_mmio_bridge_command cmd = {
           .target_bdf = bdf,
           .target_bar = bar,
           .offset = offset,
           .value = value,
           .command = 1,  /* WRITE */
           .size = size,
           .status = 0,   /* PENDING */
       };

       /* Write command to queue */
       cmds[slot] = cmd;
       wmb();

       /* Update producer index */
       meta->producer_idx++;

       /* Poll for completion (or use interrupt) */
       while (cmds[slot].status == 0)
           cpu_relax();

       return (cmds[slot].status == 1) ? 0 : -EIO;
   }
