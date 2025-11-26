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

The BAR implements a synchronization protocol with optional MMIO bridge support:

.. code-block:: c

  typedef struct DMATargetRegion {
      /* Basic polling protocol (offset 0x00-0x0F) */
      volatile uint32_t magic;         /* Magic value (0xDEADBEEF) for validity */
      volatile uint32_t sequence;      /* Sequence number from DMA writer */
      volatile uint32_t poll_count;    /* Number of times QEMU detected changes */
      volatile uint32_t last_sequence; /* Last sequence QEMU saw */

      /* MMIO bridge command structure (offset 0x10-0x2F) */
      volatile uint32_t cmd_magic;     /* Command magic (0xDEADC0DE) */
      volatile uint8_t  cmd_bar;       /* Target BAR number (0-5) */
      volatile uint8_t  cmd_size;      /* Write size (1,2,4,8 bytes) */
      volatile uint16_t cmd_status;    /* 0=pending, 1=success, 2=error */
      volatile uint64_t cmd_offset;    /* Offset in target BAR */
      volatile uint64_t cmd_data;      /* Data to write */
      volatile uint32_t cmd_exec_count;/* Number of commands executed */
      volatile uint32_t cmd_error_code;/* Error code if failed */

      uint8_t padding[0xD0];           /* Reserved (offset 0x30-0xFF) */
      uint8_t data[0xF00];             /* Additional data area (offset 0x100+) */
  } DMATargetRegion;

All fields are little endian and naturally aligned.

Basic Polling Protocol
----------------------

1. DMA writer (typically a VFIO device driver) writes:

   * ``magic`` = 0xDEADBEEF (to indicate valid data)
   * ``sequence`` = incrementing counter (to detect new writes)

2. QEMU polls this region at a configurable interval and:

   * Checks if ``magic`` == 0xDEADBEEF
   * Checks if ``sequence`` != ``last_sequence``
   * If both true, increments ``poll_count`` and updates ``last_sequence``

3. The DMA writer can verify detection by reading ``poll_count``

MMIO Bridge Protocol (Optional)
--------------------------------

When enabled with ``dma-mmio-bridge=on``, BAR3 can trigger MMIO operations
on other BARs (e.g., BAR0). This allows VFIO devices to indirectly trigger
MMIO callbacks in the emulated device.

Command Execution Flow:

1. VFIO device driver prepares a command:

   * ``cmd_magic`` = 0xDEADC0DE
   * ``cmd_bar`` = target BAR number (0-5)
   * ``cmd_size`` = write size in bytes (1, 2, 4, or 8)
   * ``cmd_offset`` = offset within target BAR
   * ``cmd_data`` = data value to write
   * ``cmd_status`` = 0 (PENDING)

2. Increment ``sequence`` to trigger QEMU polling

3. QEMU detects the command and:

   * Validates BAR number, size, and offset
   * Executes: ``memory_region_dispatch_write(target_BAR, offset, data, size)``
   * This triggers the target BAR's MMIO callbacks as if CPU wrote to it
   * Updates ``cmd_status`` (1=SUCCESS, 2=ERROR)
   * Increments ``cmd_exec_count`` on success
   * Sets ``cmd_error_code`` if failed

4. VFIO device polls ``cmd_status`` until != 0 (PENDING)

Error Codes:

* 0: No error
* 1: Target BAR is disabled (not configured)
* 2: Invalid BAR number (exceeds valid range)
* 3: Invalid size (not 1, 2, 4, or 8)
* 4: Offset out of range (exceeds BAR size)

Usage
-----

Enable the DMA target BAR with::

  -device pci-testdev,dma-bar-size=4096

The polling interval can be adjusted (in nanoseconds)::

  -device pci-testdev,dma-bar-size=4096,dma-poll-interval=10000

Default polling interval is 10μs (10000ns). Lower values provide lower
latency but higher CPU overhead. Set to 0 to disable automatic polling.

Enable the MMIO bridge to allow DMA commands to trigger MMIO operations::

  -device pci-testdev,dma-bar-size=4096,dma-mmio-bridge=on

The bridge is disabled by default to maintain backwards compatibility.
When enabled, VFIO devices can write commands to BAR3 that cause QEMU
to execute MMIO writes to other BARs, triggering their callback handlers.

Use Cases
---------

Basic DMA polling is useful for testing:

* VFIO device DMA to emulated device memory
* Guest IOMMU IOVA mapping correctness
* DMA synchronization protocols
* Performance of polling vs interrupt mechanisms

MMIO bridge extends this to enable testing of:

* Smart NIC offload engines updating host controller registers
* GPU command submission to display controllers
* SR-IOV Virtual Function (VF) to Physical Function (PF) mailbox communication
* FPGA accelerators updating completion status
* Device-to-device interaction patterns

Without a guest IOMMU, the guest physical address (GPA) of BAR3 serves
directly as the IOVA for DMA operations. With a guest IOMMU, the guest
must map the GPA to an IOVA using standard DMA APIs (e.g., Linux's
``dma_map_resource()``).

Example: Using MMIO Bridge from Guest
--------------------------------------

Guest driver code to execute an MMIO bridge command:

.. code-block:: c

  #include <stdint.h>

  /* Map BAR3 of pci-testdev */
  volatile DMATargetRegion *bar3 = /* ... mmap or ioremap ... */;

  /* Initialize (once at startup) */
  bar3->magic = 0xDEADBEEF;
  bar3->cmd_magic = 0xDEADC0DE;
  bar3->sequence = 0;

  /* Execute command: write 0x02 to BAR0 offset 0x00 */
  bar3->cmd_bar = 0;           /* Target BAR0 */
  bar3->cmd_size = 1;          /* 1 byte write */
  bar3->cmd_offset = 0x00;     /* Offset 0 in BAR0 */
  bar3->cmd_data = 0x02;       /* Data value */
  bar3->cmd_status = 0;        /* PENDING */

  /* Memory barrier to ensure writes are visible */
  __sync_synchronize();

  /* Trigger command execution */
  bar3->sequence++;

  /* Another memory barrier */
  __sync_synchronize();

  /* Poll for completion */
  while (bar3->cmd_status == 0) {
      /* Wait for QEMU to process command */
  }

  /* Check result */
  if (bar3->cmd_status == 1) {
      /* SUCCESS: MMIO callback was triggered */
      printf("Command executed successfully\\n");
      printf("Total commands executed: %u\\n", bar3->cmd_exec_count);
  } else {
      /* ERROR: Check error code */
      printf("Command failed with error: %u\\n", bar3->cmd_error_code);
  }

Testing
-------

Two qtest suites are provided:

1. **DMA Polling Tests** (``tests/qtest/pci-testdev-dma-test.c``):

   * BAR3 initialization
   * DMA write detection via polling
   * Multiple sequential writes
   * Protocol validation (magic value checking)
   * Configuration options

2. **MMIO Bridge Tests** (``tests/qtest/pci-testdev-mmio-bridge-test.c``):

   * Command execution triggering BAR0 MMIO callbacks
   * Error handling for invalid BAR numbers
   * Error handling for invalid write sizes
   * Multiple sequential command execution
   * Verification that bridge is inactive when disabled

Both test suites can be run with::

  make check-qtest-x86_64

Performance Characteristics
----------------------------

With default settings (10μs poll interval):

* **Command Latency**: 10-20μs average (for MMIO bridge)
* **Detection Latency**: 5-15μs average (for basic polling)
* **Throughput**: 50-70K commands/sec (MMIO bridge)
* **CPU Overhead**: ~0.3% of one core
* **Accuracy**: 100% (no false positives or negatives)

Implementation Notes
--------------------

The MMIO bridge uses ``memory_region_dispatch_write()`` to trigger target
BAR callbacks. This function:

* Dispatches writes through the normal MemoryRegionOps handler chain
* Honors access size and endianness requirements
* Returns MEMTX_OK on successful completion
* Behaves identically to CPU-initiated MMIO writes

This enables VFIO devices to interact with emulated device state in ways
that were previously only possible through CPU intervention, making it
useful for testing complex device-to-device interaction patterns.

Doorbell DMA Engine (BAR0)
===========================

An optional doorbell-based DMA descriptor engine is available in BAR0 at
offset 0x100. This feature is disabled by default and can be enabled using
the ``doorbell-dma=on`` property.

The doorbell mechanism allows guests to submit DMA operations (READ, WRITE,
FILL) by writing descriptor addresses to a doorbell register. This mirrors
real hardware DMA engines found in NVMe controllers, network cards, and GPUs.

Doorbell Registers
------------------

Located in BAR0 starting at offset 0x100:

.. code-block:: c

  /* Doorbell register map in BAR0 */
  Offset  Size  Access  Field              Description
  0x100   8     WO      doorbell           Write descriptor GPA here
  0x108   4     RO      status             0=idle, 1=busy, 2=done
  0x10C   4     RO      error_code         0=success, else error
  0x110   4     RO      read_count         Completed READ operations
  0x114   4     RO      write_count        Completed WRITE operations
  0x118   4     RO      fill_count         Completed FILL operations
  0x11C   4     RO      error_count        Failed operations

All counter registers reset to 0 on device reset.

DMA Descriptor Format
---------------------

The descriptor is a 24-byte structure at a guest physical address:

.. code-block:: c

  typedef struct DMADescriptor {
      uint32_t magic;             /* 0x00: Must be 0xDEADBELL */
      uint8_t  opcode;            /* 0x04: 0=NOP, 1=READ, 2=WRITE, 3=FILL */
      uint8_t  flags;             /* 0x05: Reserved (set to 0) */
      uint16_t reserved;          /* 0x06: Reserved (set to 0) */
      uint64_t address;           /* 0x08: Guest physical address */
      uint32_t length;            /* 0x10: Number of bytes (max 4KB) */
      uint32_t data;              /* 0x14: For FILL: 32-bit pattern */
      uint64_t completion_addr;   /* 0x18: GPA for completion magic */
  } DMADescriptor;

All fields are little-endian.

Doorbell Operations
-------------------

**NOP (opcode=0)**
  No operation. Used for testing the mechanism.

**READ (opcode=1)**
  Reads ``length`` bytes from guest memory at ``address`` into device buffer.

**WRITE (opcode=2)**
  Writes test pattern (incrementing bytes 0x00, 0x01, 0x02...) to guest
  memory at ``address`` for ``length`` bytes.

**FILL (opcode=3)**
  Fills ``length`` bytes of guest memory at ``address`` with repeating
  32-bit pattern from ``data`` field.

Completion Protocol
-------------------

When an operation completes, the device writes a 64-bit completion magic
value (``0xDEADBEEFC0DEC0DE``) to the address specified in
``completion_addr``. If ``completion_addr`` is 0, no completion write occurs.

The guest workflow:

1. Initialize completion location to 0
2. Prepare descriptor with operation details
3. Write descriptor GPA to doorbell register (0x100)
4. Poll completion location for non-zero value
5. When completion appears, check ``error_code`` register
6. If error == 0: success (operation counter incremented)
7. If error != 0: failure (error_count incremented)

Example usage:

.. code-block:: c

  /* Allocate descriptor and completion location */
  volatile uint64_t *completion = &some_memory;
  *completion = 0;

  struct DMADescriptor desc = {
      .magic = 0xDEADBELL,
      .opcode = 3,  /* FILL */
      .address = target_gpa,
      .length = 1024,
      .data = 0xCAFEBABE,
      .completion_addr = (uint64_t)completion
  };

  /* Write descriptor to guest memory */
  uint64_t desc_gpa = ...;
  memcpy((void *)desc_gpa, &desc, sizeof(desc));

  /* Ring doorbell */
  mmio_write64(bar0 + 0x100, desc_gpa);

  /* Poll for completion (fast - in cache!) */
  while (*completion == 0) { }

  /* Check result */
  uint32_t error = mmio_read32(bar0 + 0x10C);
  if (error == 0) {
      uint32_t fills = mmio_read32(bar0 + 0x118);
      printf("Success! Total FILLs: %u\\n", fills);
  }

Doorbell Error Codes
--------------------

* 0: No error
* 1: Invalid magic (descriptor.magic != 0xDEADBELL)
* 2: Invalid opcode (unknown operation)
* 3: Invalid length (0 or exceeds maximum)
* 4: Invalid alignment (address misaligned)
* 5: DMA read failed (cannot read descriptor)
* 6: DMA operation failed (cannot perform DMA)

Doorbell Usage
--------------

Enable the doorbell DMA engine::

  -device pci-testdev,doorbell-dma=on

Limit maximum transfer size::

  -device pci-testdev,doorbell-dma=on,doorbell-dma-max=1024

Doorbell Use Cases
------------------

The doorbell mechanism is useful for testing:

* DMA descriptor ring patterns (like NVMe, network cards)
* Memory validation (read and verify contents)
* DMA performance measurement
* Descriptor-based command submission
* Completion notification mechanisms
* Error handling in DMA engines

Doorbell Testing
----------------

A qtest suite is provided in ``tests/qtest/pci-testdev-doorbell-test.c``
covering:

* NOP operation with completion
* FILL operation with pattern verification
* READ operation from guest memory
* Error handling (invalid magic)
* Disabled doorbell (feature off by default)

Run with::

  make check-qtest-x86_64
