.. SPDX-License-Identifier: GPL-2.0-or-later

=========
vfio-user
=========

QEMU includes a ``vfio-user`` client. The ``vfio-user`` specification allows for
implementing (PCI) devices in userspace outside of QEMU; it is similar to
``vhost-user`` in this respect (see :doc:`virtio/vhost-user`), but can emulate arbitrary
PCI devices, not just ``virtio``. Whereas ``vfio`` is handled by the host
kernel, ``vfio-user``, while similar in implementation, is handled entirely in
userspace.

For example, SPDK includes a virtual PCI NVMe controller implementation; by
setting up a ``vfio-user`` UNIX socket between QEMU and SPDK, a VM can send NVMe
I/O to the SPDK process.

Presuming a suitable ``vfio-user`` server has opened a socket at
``/tmp/vfio-user.sock``, a device can be configured with for example:

.. code-block:: console

  --device '{"driver": "vfio-user-pci","socket": {"path": "/tmp/vfio-user.sock", "type": "unix"}}'

See `libvfio-user <https://github.com/nutanix/libvfio-user/>`_ for further
information.

P2P DMA and MMIO access
-----------------------

A vfio-user server process needs several paths to write data into the guest or
to trigger MMIO operations on QEMU-owned devices.  The mechanisms available
depend on what the target GPA maps to.

Guest RAM (memfd-backed)
~~~~~~~~~~~~~~~~~~~~~~~~

When QEMU is launched with a memfd-backed memory backend:

.. code-block:: console

  -object memory-backend-memfd,id=ram,size=512M
  -machine q35,memory-backend=ram,accel=kvm

every ``DMA_MAP`` message for guest RAM carries the memfd file descriptor via
``SCM_RIGHTS``.  libvfio-user mmaps the fd in the server process, making guest
RAM directly accessible:

* ``vfu_sgl_get()`` returns a host pointer — zero-copy reads and writes with no
  socket involvement per access.
* ``vfu_sgl_write()`` sends a ``DMA_WRITE`` message as a fallback when the region
  is not directly mappable (e.g. without ``memory-backend-memfd``).

Without ``memory-backend-memfd``, QEMU allocates guest RAM with anonymous
``mmap()``; no fd is available, ``vfu_sgl_get()`` fails, and ``vfu_sgl_write()``
must be used instead (one socket round-trip per write).

Peer device BAR (memfd-backed)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If a vfio-user server registers a BAR region with a real memfd backing (via
``vfu_setup_region(..., fd, ...)``), QEMU creates a ``ram_device`` MemoryRegion
backed by that fd and includes it in subsequent ``DMA_MAP`` messages sent to
*other* connected servers.  A peer server that receives the ``DMA_MAP`` for that
BAR GPA gets a live ``vaddr`` and can ``memcpy()`` directly into the target
server's register space — zero-copy, zero socket round-trips, with no
``REGION_WRITE`` message involved.

QEMU-owned MMIO (IO-ops MemoryRegions)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Native QEMU device BARs implemented with ``memory_region_init_io()`` (IO-ops)
are not included in ``DMA_MAP`` because they have no backing memory fd.  A
server process therefore cannot reach these GPAs via the DMA path.  Three
options exist:

1. **pci-mmio-bridge ring** — a dedicated PCI device that exposes a
   memfd-backed shared ring.  The server writes ``CMD_WRITE`` commands into the
   ring (zero-copy via the DMA-mapped memfd); QEMU polls the ring and dispatches
   each command via ``memory_region_dispatch_write()``.  The bridge supports
   arbitrary BDF/BAR/offset targets.

2. **Host doorbell eventfd** (``VFIO_USER_HOST_DOORBELL_FD``) — for
   fixed-value doorbell registers (see below).

3. **DMA_WRITE with MMIO extension** — ``vfio_user_dma_write()`` now calls
   ``address_space_write(&address_space_memory, ...)`` instead of
   ``pci_dma_write()``, so ``DMA_WRITE`` messages whose GPA falls in MMIO space
   are dispatched to IO-ops handlers.  The libvfio-user companion API
   ``vfu_mmio_write()`` sends a ``VFIO_USER_DMA_WRITE`` message without
   requiring the GPA to be registered in the server's DMA table (see below).

Host MMIO Doorbell Eventfd
--------------------------

``VFIO_USER_HOST_DOORBELL_FD`` (opcode 19) eliminates the per-write socket
round-trip for MMIO doorbell registers that QEMU has registered via
``memory_region_add_eventfd()``.

How it works
~~~~~~~~~~~~

When a device model calls ``memory_region_add_eventfd()`` with
``match_data = true`` on a BAR or MMIO region, QEMU's vfio-user memory listener
intercepts the registration and:

1. Creates an ``EventNotifier`` (an ``eventfd``).
2. Registers an AIO handler on the proxy iothread: when the fd fires, QEMU calls
   ``address_space_write(gpa, datamatch, size)`` — dispatching the write through
   the flatview to the device's IO-ops handler exactly as if the guest had
   written it.
3. Sends ``VFIO_USER_HOST_DOORBELL_FD`` to the connected server with the fd via
   ``SCM_RIGHTS``.

The server receives the fd via ``vfu_setup_host_doorbell_cb()`` and rings it
whenever it needs to trigger the doorbell:

.. code-block:: c

  /* one syscall — no socket */
  uint64_t val = 1;
  write(doorbell_fd, &val, sizeof(val));

When doorbell fds are sent
~~~~~~~~~~~~~~~~~~~~~~~~~~

QEMU sends a ``HOST_DOORBELL_FD`` message for each ``match_data = true``
ioeventfd registered by a device model.  Common sources:

* **virtio devices** — per-queue notify registers are registered when the guest
  driver configures the device (e.g. ``virtio-rng-pci``, ``virtio-net-pci``).
* **pci-testdev** — registers a test doorbell at BAR0 offset 0 (value ``0xFA``,
  1 byte) unconditionally at realize time; useful for testing without a guest
  driver.
* Any device that calls ``memory_region_add_eventfd(..., match_data=true, ...)``.

Wildcard ioeventfds (``match_data = false``) are not forwarded because they
carry no fixed write value.

Performance comparison
~~~~~~~~~~~~~~~~~~~~~~

+-----------------------------+-------------------+---------------------------+
| Mechanism                   | Per-write cost    | Requirement               |
+=============================+===================+===========================+
| ``REGION_WRITE``            | 1 socket msg      | Always available          |
+-----------------------------+-------------------+---------------------------+
| ``DMA_WRITE`` (guest RAM)   | 1 socket msg      | GPA in DMA space          |
+-----------------------------+-------------------+---------------------------+
| Peer memfd BAR              | 0 (memcpy)        | Target BAR is memfd-backed|
+-----------------------------+-------------------+---------------------------+
| **Host doorbell eventfd**   | 1 eventfd write   | Device uses               |
|                             | (kernel-only)     | ``memory_region_add_      |
|                             |                   | eventfd(..., true, ...)`` |
+-----------------------------+-------------------+---------------------------+
| pci-mmio-bridge ring        | memcpy + poll     | Bridge device in guest    |
+-----------------------------+-------------------+---------------------------+

DMA_WRITE to MMIO GPAs (``vfu_mmio_write``)
-------------------------------------------

``vfio_user_dma_write()`` dispatches incoming ``VFIO_USER_DMA_WRITE`` messages
via ``address_space_write(&address_space_memory, ...)`` rather than
``pci_dma_write()``.  This means the write traverses the guest's full physical
address flatview:

* **Guest RAM GPAs** — written into backing memory as before.
* **MMIO GPAs** (IO-ops MemoryRegions: device BARs, doorbells, virtio notify
  registers) — dispatched to the device's ``.write`` IO-ops handler.
* **Unassigned or ROM GPAs** — ``MEMTX_DECODE_ERROR`` returned as ``ENODEV``
  to the server; no memory is modified.

On the server side, ``vfu_mmio_write()`` (from libvfio-user) sends a
``VFIO_USER_DMA_WRITE`` message for an arbitrary GPA without requiring that GPA
to be in the server's DMA address table:

.. code-block:: c

  /* Write 4 bytes to a QEMU device's BAR register at GPA 0xfebe5000 */
  uint32_t val = 0x00000001;
  int ret = vfu_mmio_write(ctx, 0xfebe5000, &val, sizeof(val));

This is the **slow path** for MMIO writes (one socket round-trip per call).
For high-frequency doorbells, prefer the ``HOST_DOORBELL_FD`` mechanism (one
``eventfd_write()`` syscall, no socket) or the ``pci-mmio-bridge`` ring.

+-----------------------------+-------------------+---------------------------+
| Mechanism                   | Per-write cost    | Requirement               |
+=============================+===================+===========================+
| ``REGION_WRITE``            | 1 round-trip      | Always available          |
+-----------------------------+-------------------+---------------------------+
| ``vfu_mmio_write``          | 1 round-trip      | No registration needed;   |
| (``DMA_WRITE`` to MMIO)     |                   | any GPA accepted          |
+-----------------------------+-------------------+---------------------------+
| ``HOST_DOORBELL_FD``        | 1 eventfd write   | Device uses               |
|                             | (kernel-only)     | ``memory_region_add_      |
|                             |                   | eventfd(..., true, ...)`` |
+-----------------------------+-------------------+---------------------------+
| pci-mmio-bridge ring        | memcpy + poll     | Bridge device in guest    |
+-----------------------------+-------------------+---------------------------+

pci-mmio-bridge
---------------

The ``pci-mmio-bridge`` device provides a general mechanism for a vfio-user
server to write to any MMIO target (identified by PCI BDF, BAR, and offset),
including devices that do not use ``memory_region_add_eventfd()``.

The bridge exposes a memfd-backed command ring at a guest physical address
(``shadow_gpa``) that QEMU advertises in PCI config space.  The server writes
``CMD_WRITE`` or ``CMD_READ`` commands into the ring (zero-copy, via the DMA-mapped
memfd received in ``DMA_MAP``); QEMU's 1 ms poll timer dispatches each command
via ``memory_region_dispatch_write()`` on the target device's leaf MemoryRegion.

.. code-block:: console

  -device pci-mmio-bridge

Config space layout (all little-endian, capability base ``0x40``):

+--------+----------+------------------------------------------------------+
| Offset | Register | Description                                          |
+========+==========+======================================================+
| 0x40   | GPA_LO   | Low 32 bits of ``shadow_gpa``                        |
+--------+----------+------------------------------------------------------+
| 0x44   | GPA_HI   | High 32 bits of ``shadow_gpa``                       |
+--------+----------+------------------------------------------------------+
| 0x48   | SIZE     | Size of the shadow ring in bytes                     |
+--------+----------+------------------------------------------------------+
| 0x4C   | DEPTH    | Maximum number of command slots                      |
+--------+----------+------------------------------------------------------+
| 0x50   | OVER_LO  | (R/W) Low 32 bits of override GPA                   |
+--------+----------+------------------------------------------------------+
| 0x54   | OVER_HI  | (R/W) High 32 bits of override GPA                  |
+--------+----------+------------------------------------------------------+

Ring command format (``struct pci_mmio_bridge_command``, 24 bytes):

+--------+--------+---------------------------------------------------------+
| Offset | Size   | Field                                                   |
+========+========+=========================================================+
| 0x00   | 2      | ``target_bdf`` (bus << 8 | devfn)                       |
+--------+--------+---------------------------------------------------------+
| 0x02   | 1      | ``target_bar`` (0–5)                                    |
+--------+--------+---------------------------------------------------------+
| 0x04   | 4      | ``offset`` within BAR                                   |
+--------+--------+---------------------------------------------------------+
| 0x08   | 8      | ``value`` (write data or read result)                   |
+--------+--------+---------------------------------------------------------+
| 0x10   | 1      | ``command``: 0=NOP, 1=WRITE, 2=READ                     |
+--------+--------+---------------------------------------------------------+
| 0x11   | 1      | ``size``: access width in bytes (1/2/4/8)               |
+--------+--------+---------------------------------------------------------+
| 0x12   | 1      | ``status``: 0=PENDING, 1=COMPLETE, 2=ERROR              |
+--------+--------+---------------------------------------------------------+
| 0x20   | 4      | ``sequence``                                            |
+--------+--------+---------------------------------------------------------+

The override GPA registers (``0x50``/``0x54``) let the guest driver redirect the
ring to a GPU flat aperture allocation (e.g. ``hipHostMalloc``), enabling the
GPU to post commands directly without going through normal guest RAM.  QEMU
commits the new GPA on writes to offset ``0x50`` (LO) only.
