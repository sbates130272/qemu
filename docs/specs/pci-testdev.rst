====================
QEMU PCI test device
====================

``pci-testdev`` is a device used for testing low level IO.

The device implements up to three BARs: BAR0, BAR1 and BAR2.
Each of BAR 0+1 can be memory or IO. Guests must detect
BAR types and act accordingly.

BAR 0+1 size is up to 4K bytes each.
BAR 0+1 starts with the following header:

.. code-block:: c

  typedef struct PCITestDevHdr {
      uint8_t test;        /* write-only, starts a given test number */
      uint8_t width_type;  /*
                            * read-only, type and width of access for a given test.
                            * 1,2,4 for byte,word or long write.
                            * any other value if test not supported on this BAR
                            */
      uint8_t pad0[2];
      uint32_t offset;     /* read-only, offset in this BAR for a given test */
      uint32_t data;       /* read-only, data to use for a given test */
      uint32_t count;      /* for debugging. number of writes detected. */
      uint8_t name[];      /* for debugging. 0-terminated ASCII string. */
  } PCITestDevHdr;

All registers are little endian.

The device is expected to always implement tests 0 to N on each BAR, and to add new
tests with higher numbers.  In this way a guest can scan test numbers until it
detects an access type that it does not support on this BAR, then stop.

BAR2 is a 64bit memory BAR, without backing storage.  It is disabled
by default and can be enabled using the ``membar=<size>`` property.  This
can be used to test whether guests handle PCI BARs of a specific
(possibly quite large) size correctly.

Mirror BAR (Optional)
----------------------

The device supports an optional RAM-backed "mirror" BAR that transparently
forwards all accesses to another BAR (typically BAR0). This feature is
particularly useful for VFIO scenarios where a device needs to perform DMA
to trigger MMIO behavior.

The mirror BAR can be enabled using the following properties:

.. code-block:: none

  mirror-enabled=on           Enable mirror BAR feature
  mirror-size=<size>         Size of mirror BAR (must be power of 2)
  mirror-bar-num=<n>         Mirror BAR number 0-5 (default: 3)
  mirror-target-bar=<n>      Target BAR number 0-5 (default: 0)
  mirror-target-offset=<n>   Offset in target BAR (default: 0)
  mirror-sync-reads=on|off   Sync reads from target (default: off)
  mirror-poll-interval=<ns>  Polling interval in ns (default: 10000)

**Example Usage:**

Basic configuration (mirror entire BAR0 with 4KB window):

.. code-block:: bash

  -device pci-testdev,mirror-enabled=on,mirror-size=4096

Advanced configuration:

.. code-block:: bash

  -device pci-testdev,mirror-enabled=on,mirror-size=4096,\
          mirror-target-bar=0,mirror-target-offset=0,\
          mirror-poll-interval=10000

**How it Works:**

1. The mirror BAR is RAM-backed, making it accessible for VFIO DMA mapping
   via ``VFIO_IOMMU_MAP_DMA``.

2. CPU accesses to the mirror BAR go directly to the backing RAM.

3. A periodic timer polls the RAM for changes and forwards any writes to
   the target BAR using the device's MMIO callbacks.

4. Optionally, reads from the mirror BAR can be synchronized with the
   target BAR to fetch the current register values.

**Use Cases:**

- VFIO device performing DMA to trigger pci-testdev MMIO behavior
- Testing PCI BAR mirroring infrastructure
- Debugging device-to-device communication
