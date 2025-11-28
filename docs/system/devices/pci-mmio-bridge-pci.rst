PCI MMIO Bridge (PCI Device)
============================

The PCI MMIO Bridge PCI device provides a discoverable, standards-compliant
interface for device-to-device MMIO operations. It appears as a standard
PCI device in the guest, making it easy to discover.

**IMPORTANT**: This device uses a **hybrid architecture** to support both
guest discoverability AND VFIO DMA access:

- PCI device for discovery (vendor 0x1b36, device 0x0010)
- Shadow buffer allocated in **guest RAM** (not PCI MMIO space)
- GPA exposed via PCI config space vendor-specific registers

This architecture is critical because VFIO's Type-1 IOMMU can only map
guest RAM, not PCI MMIO space.

Overview
--------

Architecture
~~~~~~~~~~~~

Unlike a traditional PCI device that exposes functionality via BARs, the
PCI MMIO Bridge uses a hybrid model:

1. **PCI Device**: Provides guest OS discovery via standard enumeration
2. **Guest RAM**: Shadow buffer allocated as guest physical memory
3. **Config Space**: Exposes shadow buffer GPA in vendor-specific registers
4. **VFIO Compatible**: Shadow buffer can be mapped via `vfio_container_dma_map()`

This design enables:

- **Guest Discovery**: PCI enumeration finds the device automatically
- **VFIO DMA**: Real hardware can DMA to shadow buffer (IOVA = GPA)
- **Standard Drivers**: Guest uses normal PCI driver model

Device Properties
~~~~~~~~~~~~~~~~~

- **Vendor ID**: 0x1b36 (Red Hat/QEMU)
- **Device ID**: 0x0010 (PCI MMIO Bridge)
- **Class**: 0x08/0x80 (System Other)
- **Shadow Buffer**: Guest RAM at configurable GPA
- **Config Space**: Vendor registers expose GPA/size/depth

Guest Discovery
---------------

PCI Enumeration
~~~~~~~~~~~~~~~

The device appears in standard PCI enumeration:

.. code-block:: bash

   # Linux
   lspci
   # Output:
   # 00:04.0 System peripheral: Red Hat, Inc. Device 0010

   lspci -v -s 00:04.0
   # Shows PCI IDs but NO BARs (shadow buffer is in guest RAM)

Reading Shadow Buffer Location
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Guest drivers read vendor-specific config space to find shadow buffer:

.. code-block:: c

   #define PCI_MMIO_BRIDGE_CAP_OFFSET  0x40
   #define PCI_MMIO_BRIDGE_CAP_GPA_LO  0x00  /* Offset from cap base */
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

QEMU Configuration
------------------

Basic Usage
~~~~~~~~~~~

Add the device to your VM:

.. code-block:: bash

   qemu-system-x86_64 \
       -machine q35 \
       -m 4G \
       -device pci-mmio-bridge,id=mmio-bridge

This creates a bridge with defaults:

- Shadow GPA: 0x80000000 (auto-selected if 0)
- Shadow size: 4096 bytes (169 command slots)
- Polling interval: 1ms
- Enabled by default

Custom Configuration
~~~~~~~~~~~~~~~~~~~~

Specify shadow buffer location and size:

.. code-block:: bash

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=mmio-bridge,\
               shadow-gpa=0x90000000,\
               shadow-size=8192,\
               poll-interval-ns=500000

Properties:

- ``shadow-gpa``: Guest physical address for buffer (0 = auto, default: 0x80000000)
- ``shadow-size``: Buffer size in bytes (default: 4096, min: 4096)
- ``poll-interval-ns``: Polling interval in nanoseconds (default: 1000000)
- ``enabled``: Enable/disable bridge (default: true)
- ``addr``: PCI slot address (e.g., ``addr=5.0`` for slot 5)

Multiple Bridges
~~~~~~~~~~~~~~~~

Create multiple independent bridges:

.. code-block:: bash

   qemu-system-x86_64 \
       -machine q35 \
       -device pci-mmio-bridge,id=bridge0,shadow-gpa=0x80000000,addr=4.0 \
       -device pci-mmio-bridge,id=bridge1,shadow-gpa=0x81000000,addr=5.0

Each bridge has its own shadow buffer at different GPAs.

Guest Driver Usage
------------------

Linux Kernel Driver
~~~~~~~~~~~~~~~~~~~

Example PCI driver that discovers and uses the bridge:

.. code-block:: c

   #include <linux/pci.h>
   #include <linux/module.h>
   #include <linux/io.h>
   
   #define PCI_VENDOR_ID_REDHAT_QEMU  0x1b36
   #define PCI_DEVICE_ID_MMIO_BRIDGE  0x0010
   
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
       
       /* Shadow buffer is now accessible at dev->shadow_buf */
       /* Can be used for command queue operations */
       
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

VFIO Device Access
~~~~~~~~~~~~~~~~~~

For VFIO devices to DMA to the shadow buffer:

.. code-block:: c

   /* In VFIO setup code */
   
   /* Read shadow GPA from PCI config space (as above) */
   uint64_t shadow_gpa = ...;
   uint32_t shadow_size = ...;
   
   /* Map shadow buffer into VFIO container */
   /* IOVA = GPA (1:1 mapping in guest) */
   struct vfio_iommu_type1_dma_map map = {
       .argsz = sizeof(map),
       .flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
       .vaddr = (uint64_t)shadow_buf_hva,  /* Host virtual address */
       .iova = shadow_gpa,                 /* IOVA = GPA */
       .size = shadow_size,
   };
   
   ioctl(container_fd, VFIO_IOMMU_MAP_DMA, &map);
   
   /* Now VFIO device can DMA to shadow_gpa (as IOVA) */
   /* Program device to write commands to shadow_gpa */

Command Packet Format
---------------------

See ``pci-mmio-bridge.rst`` for the complete command packet structure.
The format is identical for both PCI device and machine-integrated versions.

Quick reference - Ring metadata at offset 0:

.. code-block:: c

   struct pci_mmio_ring_meta {
       uint32_t producer_idx;    // Guest/device writes here
       uint32_t consumer_idx;    // QEMU updates this
       uint32_t queue_depth;     // Max commands (read-only)
       uint32_t reserved;
   };

Commands start at offset 24 (sizeof ring_meta).

Architecture Details
--------------------

Why Not Use a BAR?
~~~~~~~~~~~~~~~~~~

**Problem**: Traditional PCI devices expose functionality via BARs (Base
Address Registers) in MMIO space. However:

1. VFIO's Type-1 IOMMU can only map **guest RAM**, not MMIO space
2. Real VFIO devices cannot DMA to PCI MMIO addresses
3. The shadow buffer MUST be guest RAM for VFIO DMA access

**Solution**: Hybrid approach:

- PCI device for discovery (standard enumeration)
- Shadow buffer in guest RAM (VFIO-compatible)
- GPA exposed via config space (guest drivers read location)

Memory Layout
~~~~~~~~~~~~~

::

   Guest Physical Memory:
   +---------------------------+
   | 0x00000000 - 0x7FFFFFFF   |  Regular RAM
   +---------------------------+
   | 0x80000000 - 0x80000FFF   |  Shadow Buffer (default, 4KB)
   |   - Ring metadata (24B)   |
   |   - Command slots (169x)  |
   +---------------------------+
   | 0x80001000 - ...          |  More RAM or devices
   +---------------------------+

The shadow buffer location is configurable via ``shadow-gpa`` property.

IOVA Mapping
~~~~~~~~~~~~

For guest perspective:

- **GPA** (Guest Physical Address): Where guest OS sees the buffer
- **IOVA** (I/O Virtual Address): Where devices use for DMA
- **Mapping**: IOVA = GPA (1:1 mapping in Type-1 IOMMU)

For host perspective:

- **HVA** (Host Virtual Address): QEMU's pointer to shadow buffer
- **GPA**: Guest's view of same memory
- QEMU allocates guest RAM and provides HVA for internal access

Use Cases
---------

GPU Direct Storage
~~~~~~~~~~~~~~~~~~

GPU writes NVMe doorbells without CPU:

1. GPU driver maps shadow buffer (ioremap GPA from config space)
2. GPU DMA engine configured with shadow_gpa as IOVA
3. GPU writes WRITE command to shadow buffer
4. QEMU processes command, updates NVMe doorbell
5. NVMe processes I/O

Multi-Device Coordination
~~~~~~~~~~~~~~~~~~~~~~~~~~

FPGA → GPU synchronization:

1. Both devices map shadow buffer via VFIO IOMMU
2. FPGA completes work, writes READ command to get GPU status
3. GPU updates shared register via WRITE command
4. All via DMA, no CPU involvement

Comparison with Machine Integration
------------------------------------

+-------------------------+----------------------+------------------------+
| Feature                 | PCI Device           | Machine Integration    |
+=========================+======================+========================+
| Discovery               | Automatic (lspci)    | Manual (fixed GPA)     |
+-------------------------+----------------------+------------------------+
| GPA Assignment          | Configurable         | Fixed or configurable  |
+-------------------------+----------------------+------------------------+
| Multiple Instances      | Easy                 | Complex                |
+-------------------------+----------------------+------------------------+
| Guest Driver            | Standard PCI driver  | Platform driver        |
+-------------------------+----------------------+------------------------+
| Configuration           | Per-device           | Per-machine            |
+-------------------------+----------------------+------------------------+
| Hotplug Support         | Yes                  | No                     |
+-------------------------+----------------------+------------------------+
| VFIO DMA                | ✅ Yes (guest RAM)   | ✅ Yes (guest RAM)     |
+-------------------------+----------------------+------------------------+
| Shadow Buffer Type      | Guest RAM            | Guest RAM              |
+-------------------------+----------------------+------------------------+

Both versions use guest RAM for VFIO compatibility. The PCI device version
adds automatic discovery.

Performance Considerations
--------------------------

Shadow Buffer Size
~~~~~~~~~~~~~~~~~~

- **4KB** (169 commands): Minimal overhead, good for light usage
- **8KB** (340 commands): Better for moderate workloads
- **16KB+**: High throughput, may increase latency

Polling Interval
~~~~~~~~~~~~~~~~

- **1ms** (default): Good balance
- **100μs**: Lower latency, higher CPU usage
- **10ms**: Lower CPU, higher latency

Troubleshooting
---------------

Device Not Found
~~~~~~~~~~~~~~~~

.. code-block:: bash

   lspci | grep 1b36
   # Should show: System peripheral: Red Hat, Inc. Device 0010

If missing:

1. Check QEMU has ``-device pci-mmio-bridge``
2. Verify PCI enumeration completed (check dmesg)

Cannot Access Shadow Buffer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If shadow buffer is not accessible:

1. **Read config space**: Verify GPA is non-zero
2. **Check permissions**: ioremap may require root/CAP_SYS_RAWIO
3. **Verify GPA**: Must be valid guest physical address

VFIO DMA Mapping Fails
~~~~~~~~~~~~~~~~~~~~~~~

If ``vfio_container_dma_map()`` returns EINVAL:

1. **Verify GPA**: Must be guest RAM, not MMIO
2. **Check alignment**: GPA should be page-aligned
3. **Size**: Must be page-aligned size
4. **Permissions**: Ensure VFIO container has correct permissions

Commands Not Processing
~~~~~~~~~~~~~~~~~~~~~~~

Enable tracing:

.. code-block:: bash

   -trace pci_mmio_bridge_pci_*
   -trace pci_mmio_bridge_*

Check:

1. Producer index is being updated
2. Queue not full (producer != consumer + queue_depth)
3. Commands have valid BDF/BAR/offset

See Also
--------

- ``pci-mmio-bridge.rst`` - Core bridge architecture and command format
- ``pci-mmio-bridge-quickstart.txt`` - Quick start guide
- ``P2P_PROXY_GUEST_ARCHITECTURE.md`` - Detailed implementation notes
