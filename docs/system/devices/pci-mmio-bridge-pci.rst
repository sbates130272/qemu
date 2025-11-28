PCI MMIO Bridge (PCI Device)
============================

The PCI MMIO Bridge PCI device provides a discoverable, standards-compliant
interface for device-to-device MMIO operations. It appears as a standard
PCI device in the guest, making it easy to discover and use.

Overview
--------

The PCI MMIO Bridge device exposes the generic PCI MMIO Bridge functionality
as a PCI device with:

- **Vendor ID**: 0x1b36 (Red Hat/QEMU)
- **Device ID**: 0x0010 (PCI MMIO Bridge)
- **Class**: 0x08/0x80 (System Other)
- **BAR0**: Shadow buffer (command queue) - 4KB to 64KB configurable

This makes the bridge:

1. **Discoverable** - Visible in ``lspci`` and PCI enumeration
2. **Standard** - Uses PCI config space and BARs
3. **Flexible** - GPA assigned by PCI enumeration (or can be fixed)
4. **Multiple** - Multiple bridges can coexist on the same VM

Guest Discovery
---------------

Unlike the machine-integrated version, the PCI device is automatically
discoverable by guest operating systems.

From Linux Guest
~~~~~~~~~~~~~~~~

Check for device:

.. code-block:: bash

   # List all PCI devices
   lspci
   # Output includes:
   # 00:04.0 System peripheral: Red Hat, Inc. Device 0010

   # Get detailed info
   lspci -v -s 00:04.0
   # Shows:
   #   Region 0: Memory at <address> (32-bit, non-prefetchable) [size=4K]

   # Read from sysfs
   cat /sys/bus/pci/devices/0000:00:04.0/vendor  # Should show 0x1b36
   cat /sys/bus/pci/devices/0000:00:04.0/device  # Should show 0x0010

From Windows Guest
~~~~~~~~~~~~~~~~~~

The device appears in Device Manager under "System Devices" with:

- Hardware ID: ``PCI\VEN_1B36&DEV_0010``
- Compatible ID: ``PCI\CC_0880``

QEMU Configuration
------------------

Basic Usage
~~~~~~~~~~~

Add the device to your VM:

.. code-block:: bash

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=mmio-bridge

This creates a bridge with default settings:

- BAR0 size: 4096 bytes (169 command slots)
- Polling interval: 1ms
- Enabled by default

Custom Configuration
~~~~~~~~~~~~~~~~~~~~

Adjust BAR size and polling:

.. code-block:: bash

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=mmio-bridge,\
               bar-size=8192,\
               poll-interval-ns=500000

Parameters:

- ``bar-size``: Shadow buffer size (4096-65536 bytes, must be power of 2)
- ``poll-interval-ns``: Polling interval in nanoseconds (default: 1000000)
- ``enabled``: Enable/disable bridge (default: true)
- ``addr``: PCI address (e.g., ``addr=5.0`` for slot 5)

Multiple Bridges
~~~~~~~~~~~~~~~~

Create multiple independent bridges:

.. code-block:: bash

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=mmio-bridge-0,addr=4.0 \
       -device pci-mmio-bridge,id=mmio-bridge-1,addr=5.0

Each bridge has its own command queue and operates independently.

Guest Driver Usage
------------------

Linux Kernel Driver
~~~~~~~~~~~~~~~~~~~

Example PCI driver for the bridge:

.. code-block:: c

   #include <linux/pci.h>
   #include <linux/module.h>
   
   #define PCI_VENDOR_ID_REDHAT_QEMU  0x1b36
   #define PCI_DEVICE_ID_MMIO_BRIDGE  0x0010
   
   static const struct pci_device_id mmio_bridge_pci_tbl[] = {
       { PCI_DEVICE(PCI_VENDOR_ID_REDHAT_QEMU,
                    PCI_DEVICE_ID_MMIO_BRIDGE) },
       { 0, }
   };
   MODULE_DEVICE_TABLE(pci, mmio_bridge_pci_tbl);
   
   static int mmio_bridge_probe(struct pci_dev *pdev,
                                const struct pci_device_id *id)
   {
       void __iomem *bar0;
       struct pci_mmio_ring_meta *meta;
       int err;
       
       err = pci_enable_device(pdev);
       if (err)
           return err;
       
       err = pci_request_regions(pdev, "pci-mmio-bridge");
       if (err)
           goto err_disable;
       
       bar0 = pci_iomap(pdev, 0, 0);
       if (!bar0) {
           err = -ENOMEM;
           goto err_release;
       }
       
       meta = (struct pci_mmio_ring_meta *)bar0;
       pr_info("PCI MMIO Bridge: queue_depth=%u\n",
               ioread32(&meta->queue_depth));
       
       /* Store for later use */
       pci_set_drvdata(pdev, bar0);
       return 0;
       
   err_release:
       pci_release_regions(pdev);
   err_disable:
       pci_disable_device(pdev);
       return err;
   }
   
   static void mmio_bridge_remove(struct pci_dev *pdev)
   {
       void __iomem *bar0 = pci_get_drvdata(pdev);
       
       pci_iounmap(pdev, bar0);
       pci_release_regions(pdev);
       pci_disable_device(pdev);
   }
   
   static struct pci_driver mmio_bridge_driver = {
       .name       = "pci-mmio-bridge",
       .id_table   = mmio_bridge_pci_tbl,
       .probe      = mmio_bridge_probe,
       .remove     = mmio_bridge_remove,
   };
   
   module_pci_driver(mmio_bridge_driver);
   MODULE_LICENSE("GPL");

Userspace Access (Linux)
~~~~~~~~~~~~~~~~~~~~~~~~~

Access via sysfs (requires root):

.. code-block:: c

   #include <stdio.h>
   #include <fcntl.h>
   #include <sys/mman.h>
   #include <stdint.h>
   
   int main() {
       int fd;
       void *bar0;
       struct pci_mmio_ring_meta {
           uint32_t producer_idx;
           uint32_t consumer_idx;
           uint32_t queue_depth;
           uint32_t reserved;
       } *meta;
       
       fd = open("/sys/bus/pci/devices/0000:00:04.0/resource0",
                 O_RDWR | O_SYNC);
       if (fd < 0) {
           perror("open");
           return 1;
       }
       
       bar0 = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                   MAP_SHARED, fd, 0);
       if (bar0 == MAP_FAILED) {
           perror("mmap");
           return 1;
       }
       
       meta = (struct pci_mmio_ring_meta *)bar0;
       
       printf("Queue depth: %u\n", meta->queue_depth);
       printf("Producer: %u\n", meta->producer_idx);
       printf("Consumer: %u\n", meta->consumer_idx);
       
       munmap(bar0, 4096);
       close(fd);
       return 0;
   }

Compile and run:

.. code-block:: bash

   gcc -o check-bridge check-bridge.c
   sudo ./check-bridge

Command Packet Format
---------------------

Commands are written to BAR0 using the same format as the machine-integrated
version. See ``pci-mmio-bridge.rst`` for detailed packet structure.

Quick reference:

.. code-block:: c

   struct pci_mmio_command {
       uint16_t target_bdf;      // Bus:Device:Function
       uint8_t  target_bar;      // Which BAR (0-5)
       uint8_t  reserved1;
       uint32_t offset;          // Offset within BAR
       uint64_t value;           // Value to write/read
       uint8_t  command;         // 1=WRITE, 2=READ
       uint8_t  size;            // 1, 2, 4, or 8 bytes
       uint8_t  status;          // 0=PENDING, 1=COMPLETE, 2=ERROR
       uint8_t  reserved2;
       uint32_t sequence;        // Command sequence number
   } __attribute__((packed));

Ring buffer metadata (first 16 bytes of BAR0):

.. code-block:: c

   struct pci_mmio_ring_meta {
       uint32_t producer_idx;    // Guest writes here
       uint32_t consumer_idx;    // QEMU reads from here
       uint32_t queue_depth;     // Max commands
       uint32_t reserved;
   } __attribute__((packed));

Comparison with Machine Integration
------------------------------------

+-------------------------+----------------------+------------------------+
| Feature                 | PCI Device           | Machine Integration    |
+=========================+======================+========================+
| Discovery               | Automatic (lspci)    | Manual (/dev/mem)      |
+-------------------------+----------------------+------------------------+
| GPA Assignment          | PCI enumeration      | Fixed or configurable  |
+-------------------------+----------------------+------------------------+
| Multiple Instances      | Easy (-device x N)   | Complex                |
+-------------------------+----------------------+------------------------+
| Guest Driver            | Standard PCI driver  | Platform driver        |
+-------------------------+----------------------+------------------------+
| Configuration           | Per-device           | Per-machine            |
+-------------------------+----------------------+------------------------+
| Hotplug Support         | Yes                  | No                     |
+-------------------------+----------------------+------------------------+

**Recommendation**: Use the PCI device version for new deployments. It's more
standard, more flexible, and easier for guests to discover.

Performance Considerations
--------------------------

BAR Size
~~~~~~~~

- **4KB** (169 commands): Good for light usage, minimal memory overhead
- **8KB** (340 commands): Better for moderate workloads
- **16KB** (682 commands): High-throughput scenarios
- **32KB+**: Very high throughput, may increase latency

Polling Interval
~~~~~~~~~~~~~~~~

- **1ms** (default): Good balance for most workloads
- **100μs**: Lower latency, higher CPU usage
- **10ms**: Lower CPU usage, higher latency

Rule of thumb: ``poll_interval_ns`` should be ~10x your expected command rate.

Debugging
---------

Enable Tracing
~~~~~~~~~~~~~~

.. code-block:: bash

   qemu-system-x86_64 \
       ... \
       -trace 'pci_mmio_bridge_pci_*' \
       -trace 'pci_mmio_bridge_write' \
       -trace 'pci_mmio_bridge_read'

Monitor Commands
~~~~~~~~~~~~~~~~

Query device info:

.. code-block:: text

   (qemu) info pci
   Bus  0, device   4, function 0:
     System peripheral: PCI device 1b36:0010
       BAR0: 32 bit memory at 0xfea00000 [0xfea00fff].
       id "mmio-bridge"

Common Issues
-------------

Device Not Found
~~~~~~~~~~~~~~~~

If ``lspci`` doesn't show the device:

1. Check QEMU command line includes ``-device pci-mmio-bridge``
2. Verify PCI enumeration completed (watch ``dmesg`` during boot)
3. Try explicit PCI address: ``-device pci-mmio-bridge,addr=4.0``

BAR Not Mapped
~~~~~~~~~~~~~~

If BAR0 shows as disabled:

1. Ensure PCI device is enabled (``setpci -s 00:04.0 COMMAND``should include bit 1)
2. Check if guest OS assigned an address to the BAR
3. Try booting without ``-S`` (start paused) flag

Commands Not Processing
~~~~~~~~~~~~~~~~~~~~~~~

If commands stay in PENDING status:

1. Check ``enabled`` property is true
2. Verify producer index is being updated
3. Enable trace events to see if polling is happening
4. Check that target device BDF is correct

See Also
--------

- ``pci-mmio-bridge.rst`` - Generic bridge architecture and command format
- ``pci-mmio-bridge-quickstart.txt`` - Quick start guide
- ``GUEST_VISIBILITY.md`` - Guest discovery mechanisms
- ``P2P_PROXY_GUEST_ARCHITECTURE.md`` - Architecture details

