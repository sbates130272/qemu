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

Peer access to other devices' BARs
----------------------------------

By default a ``vfio-user`` server can reach guest RAM with ``DMA_READ`` and
``DMA_WRITE``, and nothing else: QEMU only tells it about RAM (``DMA_MAP``), so
an address inside another device's BAR, such as a doorbell, is unknown to the
server's DMA table. Setting ``x-peer-mmio=on`` on the ``vfio-user-pci`` device
makes QEMU also announce the memory BARs of the *other* PCI devices in the guest
to that server. They are announced without a file descriptor, so the server
cannot map them: it accesses them with ``DMA_READ`` and ``DMA_WRITE`` messages,
and QEMU performs those as ordinary MMIO accesses on the target BAR, whether
that device is a QEMU device or another ``vfio-user`` server.

.. code-block:: console

  --device '{"driver": "vfio-user-pci","socket": {"path": "/tmp/vfio-user.sock", "type": "unix"}, "x-peer-mmio": true}'

The property is off by default, and applies to the one device it is set on, so
it acts like a per-device access policy. The device's own BARs, the config
space (ECAM) and platform MMIO are never announced. The server still needs PCI
Bus Master Enable set on its device for its writes to reach the target, as for
any DMA.

If a guest IOMMU translates the device, a peer BAR is announced at the IOVA the
guest mapped it at, and only while the guest keeps that mapping, so the server
can reach exactly what the guest allowed the device to reach. Without a mapping
the BAR is unreachable, as it would be for a device doing DMA on hardware.

See `libvfio-user <https://github.com/nutanix/libvfio-user/>`_ for further
information.
