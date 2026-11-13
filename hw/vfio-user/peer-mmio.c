/*
 * x-peer-mmio: let a vfio-user server reach the BARs of the other PCI devices
 * in the guest.
 *
 * A vfio-user server's DMA table is filled by DMA_MAP messages, and the VFIO
 * listener only sends those for RAM.  An address inside another device's BAR
 * is therefore unknown to the server, which cannot name it in a
 * DMA_READ/DMA_WRITE of its own.  This listener announces those BARs too, as
 * DMA regions without a file descriptor: the server can only reach them with
 * DMA_READ/DMA_WRITE messages, which QEMU turns into ordinary MMIO accesses
 * on the target BAR (the same path as a DMA access by any emulated device).
 *
 * This plays the part of the IOMMU mapping that a host would have to set up
 * before one device may reach another's BAR: the policy is per initiator, and
 * the owner of the container decides.  Only BARs of other PCI devices are
 * announced: never the container's own device (the server would otherwise
 * deadlock on its own socket), nor ECAM or platform MMIO.
 *
 * Limitations: the address space is assumed to be the system address space
 * with the PCI memory window mapped at 0 (the PC machine types), and a vIOMMU
 * in front of the device is not handled.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/vfio-user/container.h"
#include "hw/vfio-user/trace.h"
#include "qemu/error-report.h"
#include "system/memory.h"

typedef struct VFIOUserPeerRange {
    hwaddr iova;
    uint64_t size;
} VFIOUserPeerRange;

struct VFIOUserPeerMMIO {
    MemoryListener listener;
    VFIOUserContainer *container;
    DeviceState *self;      /* the vfio-user-pci device owning the container */
    GList *ranges;          /* VFIOUserPeerRange: what the server was told */
};

/*
 * Like the VFIO listener, region changes happen inside memory update
 * transactions with the BQL held, so send the resulting requests without
 * blocking and wait for them at commit.
 */
static void peer_mmio_begin(MemoryListener *listener)
{
    VFIOUserPeerMMIO *peer = container_of(listener, VFIOUserPeerMMIO, listener);

    peer->container->proxy->async_ops = true;
}

static void peer_mmio_commit(MemoryListener *listener)
{
    VFIOUserPeerMMIO *peer = container_of(listener, VFIOUserPeerMMIO, listener);
    VFIOUserProxy *proxy = peer->container->proxy;

    proxy->async_ops = false;
    vfio_user_wait_reqs(proxy);
}

/*
 * Is [start, start + size) part of a memory BAR of a PCI device other than the
 * container's own?  Leaf sections can be parts of a BAR (a BAR is often a
 * container of several regions), so match by address range and not by region.
 */
static PCIDevice *peer_mmio_bar_owner(VFIOUserPeerMMIO *peer,
                                      MemoryRegionSection *section,
                                      hwaddr start, uint64_t size)
{
    Object *owner = memory_region_owner(section->mr);
    PCIDevice *pdev;
    int i;

    if (!owner || owner == OBJECT(peer->self) ||
        !object_dynamic_cast(owner, TYPE_PCI_DEVICE)) {
        return NULL;
    }

    pdev = PCI_DEVICE(owner);
    for (i = 0; i < PCI_NUM_REGIONS; i++) {
        PCIIORegion *r = &pdev->io_regions[i];

        if (i == PCI_ROM_SLOT || !r->size || !r->memory ||
            r->addr == PCI_BAR_UNMAPPED ||
            (r->type & PCI_BASE_ADDRESS_SPACE_IO)) {
            continue;
        }
        if (start >= r->addr && start + size <= r->addr + r->size) {
            return pdev;
        }
    }

    return NULL;
}

static VFIOUserPeerRange *peer_mmio_find(VFIOUserPeerMMIO *peer, hwaddr iova,
                                         uint64_t size)
{
    GList *l;

    for (l = peer->ranges; l; l = l->next) {
        VFIOUserPeerRange *range = l->data;

        if (range->iova == iova && range->size == size) {
            return range;
        }
    }

    return NULL;
}

static void peer_mmio_region_add(MemoryListener *listener,
                                 MemoryRegionSection *section)
{
    VFIOUserPeerMMIO *peer = container_of(listener, VFIOUserPeerMMIO, listener);
    VFIOUserPeerRange *range;
    PCIDevice *owner;
    hwaddr iova;
    uint64_t size;
    int ret;

    /* RAM is announced, with its fd, by the VFIO listener. */
    if (memory_region_is_ram(section->mr) ||
        memory_region_is_iommu(section->mr)) {
        return;
    }

    iova = section->offset_within_address_space;
    size = int128_get64(section->size);

    /* Sizing a 64-bit BAR can map it far outside any address width. */
    if (!size || (iova & (1ULL << 63))) {
        return;
    }

    owner = peer_mmio_bar_owner(peer, section, iova, size);
    if (!owner || peer_mmio_find(peer, iova, size)) {
        return;
    }

    ret = vfio_user_container_dma_map(peer->container, iova, size, -1, 0,
                                      section->readonly);
    if (ret) {
        warn_report("vfio-user: cannot map BAR of %s at 0x%"PRIx64
                    " size 0x%"PRIx64" for peer access: %s",
                    owner->name, iova, size, strerror(-ret));
        return;
    }

    trace_vfio_user_peer_mmio_add(owner->name, iova, size, section->readonly);

    range = g_new0(VFIOUserPeerRange, 1);
    range->iova = iova;
    range->size = size;
    peer->ranges = g_list_prepend(peer->ranges, range);
}

static void peer_mmio_region_del(MemoryListener *listener,
                                 MemoryRegionSection *section)
{
    VFIOUserPeerMMIO *peer = container_of(listener, VFIOUserPeerMMIO, listener);
    VFIOUserPeerRange *range;
    hwaddr iova = section->offset_within_address_space;
    uint64_t size = int128_get64(section->size);
    int ret;

    /*
     * Look the range up instead of re-deriving it from the BAR: by now the
     * device's BAR state may already describe the new placement.  The server
     * removes regions by exact address and size.
     */
    range = peer_mmio_find(peer, iova, size);
    if (!range) {
        return;
    }

    trace_vfio_user_peer_mmio_del(iova, size);

    ret = vfio_user_container_dma_unmap(peer->container, iova, size);
    if (ret) {
        warn_report("vfio-user: cannot unmap peer BAR at 0x%"PRIx64
                    " size 0x%"PRIx64": %s", iova, size, strerror(-ret));
    }

    peer->ranges = g_list_remove(peer->ranges, range);
    g_free(range);
}

void vfio_user_peer_mmio_register(VFIOUserContainer *container,
                                  AddressSpace *as, DeviceState *self)
{
    VFIOUserPeerMMIO *peer = g_new0(VFIOUserPeerMMIO, 1);

    peer->container = container;
    peer->self = self;
    peer->listener = (MemoryListener) {
        .name = "vfio-user-peer-mmio",
        .begin = peer_mmio_begin,
        .commit = peer_mmio_commit,
        .region_add = peer_mmio_region_add,
        .region_del = peer_mmio_region_del,
        .priority = MEMORY_LISTENER_PRIORITY_DEV_BACKEND,
    };
    container->peer_mmio = peer;

    /* Registering replays the current memory map as region_add calls. */
    memory_listener_register(&peer->listener, as);
}

void vfio_user_peer_mmio_unregister(VFIOUserContainer *container)
{
    VFIOUserPeerMMIO *peer = container->peer_mmio;

    if (!peer) {
        return;
    }

    memory_listener_unregister(&peer->listener);
    g_list_free_full(peer->ranges, g_free);
    g_free(peer);
    container->peer_mmio = NULL;
}
