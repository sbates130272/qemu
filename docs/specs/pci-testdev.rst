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

DMA Target BAR (BAR3)
=====================

BAR3 is an optional 64-bit memory BAR backed by RAM, designed for testing
DMA interactions between VFIO-assigned devices and emulated devices. It is
disabled by default and can be enabled using the ``dma-bar-size=<size>``
property (minimum 4096 bytes).

Unlike BAR0+1 which use MMIO callbacks, BAR3 is backed by actual host RAM.
This allows VFIO devices to perform DMA writes to it via the host IOMMU.
Since DMA writes bypass QEMU's normal MMIO traps, QEMU uses a polling
mechanism to detect when writes occur.

BAR3 Layout
-----------

The BAR implements a simple synchronization protocol:

.. code-block:: c

  typedef struct DMATargetRegion {
      volatile uint32_t magic;         /* Magic value (0xDEADBEEF) for validity */
      volatile uint32_t sequence;      /* Sequence number from DMA writer */
      volatile uint32_t poll_count;    /* Number of times QEMU detected changes */
      volatile uint32_t last_sequence; /* Last sequence QEMU saw */
      uint8_t data[];                  /* Additional data area */
  } DMATargetRegion;

All fields are little endian and naturally aligned.

Protocol
--------

1. DMA writer (typically a VFIO device driver) writes:

   * ``magic`` = 0xDEADBEEF (to indicate valid data)
   * ``sequence`` = incrementing counter (to detect new writes)

2. QEMU polls this region at a configurable interval and:

   * Checks if ``magic`` == 0xDEADBEEF
   * Checks if ``sequence`` != ``last_sequence``
   * If both true, increments ``poll_count`` and updates ``last_sequence``

3. The DMA writer can verify detection by reading ``poll_count``

Usage
-----

Enable the DMA target BAR with::

  -device pci-testdev,dma-bar-size=4096

The polling interval can be adjusted (in nanoseconds)::

  -device pci-testdev,dma-bar-size=4096,dma-poll-interval=10000

Default polling interval is 10μs (10000ns). Lower values provide lower
latency but higher CPU overhead. Set to 0 to disable automatic polling.

Use Cases
---------

This feature is primarily for testing:

* VFIO device DMA to emulated device memory
* Guest IOMMU IOVA mapping correctness
* DMA synchronization protocols
* Performance of polling vs interrupt mechanisms

Without a guest IOMMU, the guest physical address (GPA) of BAR3 serves
directly as the IOVA for DMA operations. With a guest IOMMU, the guest
must map the GPA to an IOVA using standard DMA APIs (e.g., Linux's
``dma_map_resource()``).

Testing
-------

A qtest suite is provided in ``tests/qtest/pci-testdev-dma-test.c`` that
can be run with::

  make check-qtest-x86_64
