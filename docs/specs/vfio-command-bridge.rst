================================
VFIO Command Bridge (Future Work)
================================

Overview
========

This document describes a proposed extension to the PCI command bridge
infrastructure to support VFIO-to-VFIO and VFIO-to-emulated device
communication. This builds on the generic command bridge implemented in
the base patch series.

**Status**: Design proposal / Future work

Motivation
==========

The current command bridge infrastructure enables:

1. VFIO device → Emulated device communication (implemented)
2. Emulated device → Emulated device communication (implemented)

The natural extension is:

3. **VFIO device → VFIO device communication** (this proposal)

Use Cases
=========

SmartNIC + GPU Coordination
----------------------------

A SmartNIC offloads packet processing but needs to coordinate with a GPU
for compute operations::

    -device vfio-pci,id=nic,host=0000:01:00.0,\
            cmd-bridge-enabled=on,\
            cmd-bridge-target=gpu

    -device vfio-pci,id=gpu,host=0000:02:00.0

FPGA + Accelerator Pipelines
-----------------------------

Multiple FPGA or accelerator cards coordinate in a processing pipeline::

    -device vfio-pci,id=stage1,host=0000:03:00.0,\
            cmd-bridge-enabled=on,\
            cmd-bridge-target=stage2

    -device vfio-pci,id=stage2,host=0000:04:00.0,\
            cmd-bridge-enabled=on,\
            cmd-bridge-target=stage3

Proposed Architecture
=====================

Extended Target Resolution
--------------------------

The current ``PCICommandBridgeGetBarFn`` callback resolves BAR numbers to
``MemoryRegion`` pointers for emulated devices. The extension adds:

.. code-block:: c

    typedef struct PCICommandBridgeTarget {
        MemoryRegion *mr;       /* For emulated devices */
        VFIODevice *vfio_dev;   /* For VFIO devices */
        uint8_t bar_num;
        bool is_vfio;
    } PCICommandBridgeTarget;

    typedef PCICommandBridgeTarget (*PCICommandBridgeResolveTargetFn)
        (PCIDevice *pci_dev, uint8_t bar_num);

VFIO Forwarding Mechanism
--------------------------

For VFIO targets, commands are forwarded using::

    /* VFIO write */
    pwrite(vfio_dev->fd, &data, size, region->fd_offset + offset);

    /* VFIO read */
    pread(vfio_dev->fd, &data, size, region->fd_offset + offset);

This uses the VFIO device file descriptor and region offsets, avoiding
the need for the guest to have direct access to target BARs.

Implementation Plan
===================

Phase 1: Core VFIO Support
---------------------------

**Files to Modify:**

- ``include/hw/pci/pci_command_bridge.h``

  * Add ``PCICommandBridgeTarget`` structure
  * Add ``resolve_target`` callback pointer
  * Add ``target_device_id`` property

- ``hw/pci/pci-command-bridge.c``

  * Extend polling handler for VFIO targets
  * Add ``pci_command_bridge_init_ex()`` for VFIO-aware init
  * Implement pwrite/pread forwarding under ``#ifdef CONFIG_VFIO``

- ``hw/vfio/pci.c``

  * Add command bridge state to ``VFIOPCIDevice``
  * Add command bridge properties
  * Integrate into realize/unrealize/reset

Phase 2: Testing
-----------------

New QTests:

- ``tests/qtest/vfio-command-bridge-test.c``

  * Mock VFIO device creation
  * VFIO-to-emulated forwarding tests
  * VFIO-to-VFIO forwarding tests
  * Error handling and edge cases

Phase 3: Documentation
----------------------

- Update ``docs/specs/pci-testdev.rst`` with VFIO examples
- Add ``docs/specs/vfio-command-bridge.rst`` (this file)
- Update cover letter with VFIO use cases

Performance Considerations
==========================

Latency Comparison
------------------

=================================  ===========  =====================
Approach                           Latency      Guest Overhead
=================================  ===========  =====================
Native HW (PCIe TLP)               ~100-500ns   None
Current: VFIO→Emulated             ~10μs+       Minimal (DMA write)
Proposed: VFIO→VFIO                ~10μs+       Minimal (DMA write)
Future: Interrupt-driven           ~1-5μs       Minimal (MMIO write)
=================================  ===========  =====================

Optimization Opportunities
--------------------------

1. **Interrupt-driven forwarding**: Replace polling with eventfd
   notification (~5-10x latency improvement)

2. **Batched operations**: Process multiple commands per poll cycle

3. **mmap optimization**: If target VFIO BAR is mmap'd to QEMU's
   address space, use memcpy instead of pwrite

4. **Hardware offload**: Use Intel ENQCMD or AMD equivalent if
   available

Security & Isolation
====================

Access Control
--------------

QEMU acts as the security boundary:

- Validates all command parameters
- Enforces BAR number restrictions
- Prevents out-of-bounds accesses
- Logs/traces all operations

Isolation Guarantees
--------------------

- Source device cannot directly DMA to target device
- All operations mediated by QEMU
- Rate limiting via polling interval
- Per-device access control lists (future)

Device Isolation
----------------

Each VFIO device maintains its own IOMMU context, ensuring:

- DMA isolation between devices
- Separate interrupt domains
- Independent fault handling

Limitations
===========

1. **Latency**: ~10μs is acceptable for control plane but not data path

2. **Throughput**: Polling-based approach limits command rate to
   ~100K commands/sec

3. **Compatibility**: Requires CONFIG_VFIO at compile time

4. **Guest Awareness**: Guest drivers must implement the command
   protocol

5. **No Direct DMA**: Cannot replace direct device-to-device DMA for
   bulk data transfer

When to Use
===========

✅ **Good Fit:**

- Mailbox/doorbell communication
- Configuration and discovery
- Function-level reset coordination
- Debug/telemetry/tracing
- Infrequent control operations

❌ **Poor Fit:**

- Data path operations
- High-frequency operations (>100K/sec)
- Real-time requirements
- Bulk data transfer

Future Enhancements
===================

1. **Virtio Integration**: Expose command bridge via virtio for
   standardized guest drivers

2. **PCIe P2P Support**: Coordinate with kernel PCIe peer-to-peer DMA

3. **IOMMU Integration**: Leverage IOMMU features for better isolation

4. **Hardware Offload**: Integrate with PCIe TLP routing or similar

5. **Multi-Queue**: Support multiple command queues per device

References
==========

- `PCI Command Bridge Infrastructure <pci-testdev.html#command-bridge>`_
- `VFIO User Guide <https://www.kernel.org/doc/Documentation/vfio.txt>`_
- `QEMU VFIO Documentation <../devel/vfio.html>`_

