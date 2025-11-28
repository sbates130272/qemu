PCI MMIO Bridge
===============

The PCI MMIO bridge provides a device-agnostic mechanism for PCI devices
to perform MMIO (Memory-Mapped I/O) operations on other PCI devices via
DMA-accessible command packets. This enables software-defined PCIe
peer-to-peer (P2P) communication between any combination of emulated and
real VFIO devices.

Overview
--------

Traditional PCIe peer-to-peer (P2P) requires specific hardware topology
(PCIe switches, disabled ACS) and often device-specific implementations.
The PCI MMIO bridge solves this by providing a shared command queue in
guest RAM that any device can use to issue MMIO operations to any other
device's BARs.

This is particularly useful for:

* **GPU-NVMe integration**: GPU writes NVMe doorbells via DMA instead of
  CPU MMIO, reducing CPU overhead
* **Multi-GPU coordination**: GPUs update each other's registers for
  synchronization
* **Accelerator chaining**: FPGA → GPU → NVMe pipelines with minimal CPU
  involvement
* **VFIO device coordination**: Real hardware devices coordinating with
  emulated devices

Architecture
------------

Command Queue Structure
~~~~~~~~~~~~~~~~~~~~~~~

The bridge uses a ring buffer allocated in guest RAM at a configurable
guest physical address (default ``0x80000000``). The first 24 bytes
contain metadata, followed by command slots:

.. code-block:: c

   struct pci_mmio_ring_meta {
       uint32_t producer_idx;  /* Written by initiator */
       uint32_t consumer_idx;  /* Written by QEMU */
       uint32_t queue_depth;   /* Number of available slots */
       uint32_t reserved[3];
   };

   struct pci_mmio_command {
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

With the default 4KB size, the queue provides 169 command slots.

Processing Model
~~~~~~~~~~~~~~~~

QEMU polls the command queue periodically (default 1ms interval). When
the producer index differs from the consumer index:

1. QEMU reads pending commands from the queue
2. For each command:
   
   * Locates the target PCI device by BDF
   * Dispatches MMIO read/write to the target device's BAR
   * Updates the command status field (complete or error)
   * Updates the result value (for reads)

3. Updates the consumer index
4. Reschedules the next poll

Configuration
-------------

Basic Usage
~~~~~~~~~~~

Enable the PCI MMIO bridge on a PC machine:

.. parsed-literal::

   |qemu_system_x86| -M pc,pci-mmio-bridge-enabled=true

Optional Configuration
~~~~~~~~~~~~~~~~~~~~~~

Configure the guest physical address and polling interval:

.. parsed-literal::

   |qemu_system_x86| -M pc,pci-mmio-bridge-enabled=true,\\
                        pci-mmio-bridge-gpa=0x80000000,\\
                        pci-mmio-bridge-poll-interval=1000000

Parameters:

* ``pci-mmio-bridge-enabled`` - Enable the bridge (default: ``false``)
* ``pci-mmio-bridge-gpa`` - Guest physical address for command queue
  (default: ``0x80000000``, must be page-aligned)
* ``pci-mmio-bridge-poll-interval`` - Polling interval in nanoseconds
  (default: ``1000000`` = 1ms)

**Important**: The GPA must not conflict with guest RAM or other device
memory regions.

Guest Software Interface
------------------------

Discovery
~~~~~~~~~

Guest software can discover the bridge through:

1. **Hardcoded GPA**: If the hypervisor and guest agree on a fixed
   address (e.g., ``0x80000000``)
2. **ACPI table**: Future work - expose via custom ACPI table
3. **Virtio-MMIO**: Future work - expose via virtio device

Submitting Commands
~~~~~~~~~~~~~~~~~~~

Example guest driver code for writing to a PCI device's BAR:

.. code-block:: c

   #include <linux/io.h>

   volatile struct pci_mmio_ring_meta *meta;
   volatile struct pci_mmio_command *cmds;
   
   void init_bridge(void)
   {
       /* Map the command queue */
       void *va = ioremap(0x80000000, 4096);
       meta = (struct pci_mmio_ring_meta *)va;
       cmds = (struct pci_mmio_command *)(va + 
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
       struct pci_mmio_command cmd = {
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

DMA-Based Access (VFIO Devices)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For real VFIO devices (e.g., GPUs), the device can directly write
commands via DMA if the command queue is mapped into its IOMMU:

.. code-block:: c

   /* GPU kernel writes NVMe doorbell via DMA */
   __global__ void submit_nvme_command(...)
   {
       if (threadIdx.x == 0) {
           /* Write command packet to queue in host memory */
           struct pci_mmio_command *cmd = 
               &queue[producer_idx % queue_depth];
           cmd->target_bdf = nvme_bdf;
           cmd->target_bar = 0;
           cmd->offset = NVME_DOORBELL_OFFSET;
           cmd->value = sq_tail;
           cmd->command = 1;  /* WRITE */
           cmd->size = 4;
           cmd->status = 0;
           
           __threadfence_system();
           atomicAdd(&queue[0].producer_idx, 1);
       }
   }

Use Cases
---------

GPU-Accelerated NVMe
~~~~~~~~~~~~~~~~~~~~

Allow GPU to submit NVMe commands by writing doorbells via DMA:

.. parsed-literal::

   |qemu_system_x86| -M pc,pci-mmio-bridge-enabled=true \\
       -device nvme,serial=deadbeef \\
       -device vfio-pci,host=01:00.0  # GPU

The GPU can now write to NVMe doorbells without CPU involvement,
reducing submission latency and CPU overhead.

Multi-GPU Synchronization
~~~~~~~~~~~~~~~~~~~~~~~~~~

GPUs coordinate by updating each other's status registers:

.. parsed-literal::

   |qemu_system_x86| -M pc,pci-mmio-bridge-enabled=true \\
       -device vfio-pci,host=01:00.0 \\  # GPU 0
       -device vfio-pci,host=02:00.0     # GPU 1

Accelerator Chaining
~~~~~~~~~~~~~~~~~~~~

FPGA preprocesses data, GPU processes it, NVMe stores results:

.. parsed-literal::

   |qemu_system_x86| -M pc,pci-mmio-bridge-enabled=true \\
       -device vfio-pci,host=03:00.0 \\  # FPGA
       -device vfio-pci,host=01:00.0 \\  # GPU
       -device nvme,serial=storage

Performance Considerations
---------------------------

Latency
~~~~~~~

* **Polling overhead**: Commands are processed every 1ms by default
  (configurable). This adds 0-1ms latency compared to ~100ns for
  hardware P2P.
* **Optimization**: Reduce ``pci-mmio-bridge-poll-interval`` for lower
  latency at the cost of higher CPU usage.

Throughput
~~~~~~~~~~

* **Queue depth**: Default 4KB queue = 169 slots. Increase queue size
  (future work) for higher throughput scenarios.
* **Batching**: Submit multiple commands before updating producer index
  to amortize polling overhead.

Cache Coherency
~~~~~~~~~~~~~~~

The command queue is in guest RAM with MMIO ops that trigger bottom-
halves for immediate processing. Proper memory barriers (``wmb()``,
``rmb()``) must be used in guest software.

Limitations
-----------

Current Limitations
~~~~~~~~~~~~~~~~~~~

* **Bus support**: Currently only supports bus 0 (main PCI bus). Multi-
  bus topologies require future work.
* **Security**: No access control or permission checks. Any device can
  access any other device's BARs.
* **Interrupts**: No interrupt support for command completion. Guest must
  poll status field.
* **VFIO targets**: Targeting real VFIO devices requires additional
  implementation (``pread``/``pwrite`` on device fd).

Future Work
~~~~~~~~~~~

* ACPI table for discovery
* Interrupt-based completion notification
* Access control via device properties
* Multi-bus routing
* VFIO device targets
* Dynamic queue resizing
* Statistics via QMP

Debugging
---------

Enable trace events to monitor bridge activity:

.. parsed-literal::

   |qemu_system_x86| -M pc,pci-mmio-bridge-enabled=true \\
       -trace pci_mmio_bridge_init \\
       -trace pci_mmio_bridge_command \\
       -trace pci_mmio_bridge_write \\
       -trace pci_mmio_bridge_read

Available trace events:

* ``pci_mmio_bridge_init`` - Bridge initialization
* ``pci_mmio_bridge_cleanup`` - Bridge cleanup with statistics
* ``pci_mmio_bridge_command`` - Command processing start
* ``pci_mmio_bridge_write`` - MMIO write execution
* ``pci_mmio_bridge_read`` - MMIO read execution
* ``pci_mmio_bridge_write_error`` - Write error
* ``pci_mmio_bridge_read_error`` - Read error
* ``pci_mmio_bridge_device_not_found`` - Invalid target BDF
* ``pci_mmio_bridge_invalid_bar`` - Invalid BAR number
* ``pci_mmio_bridge_bar_not_mapped`` - Unmapped BAR

Example output::

   pci_mmio_bridge_init gpa=0x80000000 size=4096 queue_depth=169 
       poll_interval=1000000ns
   pci_mmio_bridge_command bdf=0x0020 cmd=1 bar=0 offset=0x1000
   pci_mmio_bridge_write bdf=0x0020 bar=0 offset=0x1000 
       value=0x12345678 size=4
   pci_mmio_bridge_cleanup total_cmds=1000 writes=800 reads=200 
       errors=0

Related Documentation
---------------------

* :doc:`../../specs/pci-ids` - PCI device identification
* :doc:`vfio-user` - VFIO device pass-through
* :doc:`nvme` - NVMe device emulation
* ``docs/pcie.txt`` - PCIe topology in QEMU

