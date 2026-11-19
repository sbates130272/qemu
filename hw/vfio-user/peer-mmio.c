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
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "system/address-spaces.h"
#include "system/memory.h"

typedef struct VFIOUserPeerIOMMU VFIOUserPeerIOMMU;

typedef struct VFIOUserPeerRange {
    hwaddr iova;
    uint64_t size;
    VFIOUserPeerIOMMU *origin;  /* NULL: a BAR section; else a guest mapping */
} VFIOUserPeerRange;

/* A translating vIOMMU in front of the device, and our view of its mappings. */
struct VFIOUserPeerIOMMU {
    VFIOUserPeerMMIO *peer;
    IOMMUMemoryRegion *iommu_mr;
    hwaddr iommu_offset;
    IOMMUNotifier n;
    QLIST_ENTRY(VFIOUserPeerIOMMU) next;
};

struct VFIOUserPeerMMIO {
    MemoryListener listener;
    VFIOUserContainer *container;
    DeviceState *self;      /* the vfio-user-pci device owning the container */
    GList *ranges;          /* VFIOUserPeerRange: what the server was told */
    QLIST_HEAD(, VFIOUserPeerIOMMU) iommus;
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
 * Is @mr, or a region it is nested in, @top?  A BAR is often a container of
 * several regions (registers, an MSI-X table, ...), and the memory core hands
 * the listener the leaf regions of the flat view, so a section has to be tied
 * back to its BAR through the region tree.  The tree is used, and not the BAR's
 * address, because a PCI bus address is not always the address the listener's
 * address space sees (machines with an offset or an alias for the PCI window).
 */
static bool peer_mmio_region_in(MemoryRegion *mr, MemoryRegion *top)
{
    while (mr) {
        Object *container;

        if (mr == top) {
            return true;
        }
        container = object_property_get_link(OBJECT(mr), "container", NULL);
        mr = container ? MEMORY_REGION(container) : NULL;
    }

    return false;
}

/*
 * The PCI device other than the container's own whose memory BAR @section is
 * part of, or NULL.  Regions a PCI device owns that are not a BAR (the legacy
 * VGA window, a LPC bridge's RCRB) do not qualify.
 */
static PCIDevice *peer_mmio_bar_owner(VFIOUserPeerMMIO *peer,
                                      MemoryRegionSection *section)
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
            (r->type & PCI_BASE_ADDRESS_SPACE_IO)) {
            continue;
        }
        if (peer_mmio_region_in(section->mr, r->memory)) {
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

/* Tell the server about [iova, iova + size), a peer BAR. */
static void peer_mmio_announce(VFIOUserPeerMMIO *peer, PCIDevice *owner,
                               hwaddr iova, uint64_t size, bool readonly,
                               VFIOUserPeerIOMMU *origin)
{
    VFIOUserPeerRange *range;
    int ret;

    if (peer_mmio_find(peer, iova, size)) {
        return;
    }

    ret = vfio_user_container_dma_map(peer->container, iova, size, -1, 0,
                                      readonly);
    if (ret) {
        warn_report("vfio-user: cannot map BAR of %s at 0x%"PRIx64
                    " size 0x%"PRIx64" for peer access: %s",
                    owner->name, iova, size, strerror(-ret));
        return;
    }

    trace_vfio_user_peer_mmio_add(owner->name, iova, size, readonly);

    range = g_new0(VFIOUserPeerRange, 1);
    range->iova = iova;
    range->size = size;
    range->origin = origin;
    peer->ranges = g_list_prepend(peer->ranges, range);
}

/* The server removes regions by exact address and size, as announced. */
static void peer_mmio_withdraw(VFIOUserPeerMMIO *peer,
                               VFIOUserPeerRange *range)
{
    int ret;

    trace_vfio_user_peer_mmio_del(range->iova, range->size);

    ret = vfio_user_container_dma_unmap(peer->container, range->iova,
                                        range->size);
    if (ret) {
        warn_report("vfio-user: cannot unmap peer BAR at 0x%"PRIx64
                    " size 0x%"PRIx64": %s", range->iova, range->size,
                    strerror(-ret));
    }

    peer->ranges = g_list_remove(peer->ranges, range);
    g_free(range);
}

/*
 * Withdraw what a guest mapping announced inside [iova, iova + size): an
 * unmap, or a change of what an address maps to.  A vIOMMU invalidates in
 * ranges that need not match the mappings, so test for overlap.  With NULL
 * @origin, withdraw whatever any guest mapping announced.
 */
static void peer_mmio_withdraw_mapped(VFIOUserPeerMMIO *peer,
                                      VFIOUserPeerIOMMU *origin,
                                      hwaddr iova, uint64_t size, bool all)
{
    GList *l = peer->ranges;

    while (l) {
        VFIOUserPeerRange *range = l->data;

        l = l->next;
        if (range->origin != origin) {
            continue;
        }
        if (all || (range->iova < iova + size &&
                    iova < range->iova + range->size)) {
            peer_mmio_withdraw(peer, range);
        }
    }
}

/*
 * The guest changed what an IOVA of this device translates to.  A peer BAR is
 * announced at the IOVA the guest chose, which is what the server has to name:
 * its DMA is translated again on the way in, so only an IOVA the guest mapped
 * for this device can reach the BAR, and the server sees exactly those.
 */
static void peer_mmio_iommu_notify(IOMMUNotifier *n, IOMMUTLBEntry *iotlb)
{
    VFIOUserPeerIOMMU *giommu = container_of(n, VFIOUserPeerIOMMU, n);
    VFIOUserPeerMMIO *peer = giommu->peer;
    hwaddr iova = iotlb->iova + giommu->iommu_offset;
    uint64_t size = (uint64_t)iotlb->addr_mask + 1;
    MemoryRegionSection target = { };
    PCIDevice *owner;
    hwaddr xlat, len = size;

    if (iotlb->target_as != &address_space_memory) {
        return;
    }

    /* An unmap, or a remap: what was announced here no longer holds. */
    peer_mmio_withdraw_mapped(peer, giommu, iova, size, false);

    if ((iotlb->perm & IOMMU_RW) == IOMMU_NONE) {
        return;
    }

    RCU_READ_LOCK_GUARD();
    target.mr = address_space_translate(&address_space_memory,
                                        iotlb->translated_addr, &xlat, &len,
                                        iotlb->perm & IOMMU_WO,
                                        MEMTXATTRS_UNSPECIFIED);
    /* RAM is announced, with its fd, by the VFIO listener's notifier. */
    if (memory_region_is_ram(target.mr) || memory_region_is_iommu(target.mr)) {
        return;
    }

    owner = peer_mmio_bar_owner(peer, &target);
    if (owner) {
        peer_mmio_announce(peer, owner, iova, size,
                           !(iotlb->perm & IOMMU_WO), giommu);
    }
}

static void peer_mmio_iommu_add(VFIOUserPeerMMIO *peer,
                                MemoryRegionSection *section)
{
    IOMMUMemoryRegion *iommu_mr = IOMMU_MEMORY_REGION(section->mr);
    VFIOUserPeerIOMMU *giommu = g_new0(VFIOUserPeerIOMMU, 1);
    Error *err = NULL;
    Int128 llend;
    int iommu_idx;

    giommu->peer = peer;
    giommu->iommu_mr = iommu_mr;
    giommu->iommu_offset = section->offset_within_address_space -
                           section->offset_within_region;
    llend = int128_add(int128_make64(section->offset_within_region),
                       section->size);
    llend = int128_sub(llend, int128_one());
    iommu_idx = memory_region_iommu_attrs_to_index(iommu_mr,
                                                   MEMTXATTRS_UNSPECIFIED);
    iommu_notifier_init(&giommu->n, peer_mmio_iommu_notify,
                        IOMMU_NOTIFIER_IOTLB_EVENTS,
                        section->offset_within_region, int128_get64(llend),
                        iommu_idx);

    if (memory_region_register_iommu_notifier(section->mr, &giommu->n, &err)) {
        error_report_err(err);
        g_free(giommu);
        return;
    }
    QLIST_INSERT_HEAD(&peer->iommus, giommu, next);

    /* What the guest has mapped already. */
    memory_region_iommu_replay(giommu->iommu_mr, &giommu->n);
}

static void peer_mmio_iommu_del(VFIOUserPeerMMIO *peer,
                                MemoryRegionSection *section)
{
    VFIOUserPeerIOMMU *giommu;

    QLIST_FOREACH(giommu, &peer->iommus, next) {
        if (giommu->iommu_mr == IOMMU_MEMORY_REGION(section->mr)) {
            memory_region_unregister_iommu_notifier(section->mr, &giommu->n);
            peer_mmio_withdraw_mapped(peer, giommu, 0, 0, true);
            QLIST_REMOVE(giommu, next);
            g_free(giommu);
            return;
        }
    }
}

static void peer_mmio_region_add(MemoryListener *listener,
                                 MemoryRegionSection *section)
{
    VFIOUserPeerMMIO *peer = container_of(listener, VFIOUserPeerMMIO, listener);
    PCIDevice *owner;
    hwaddr iova;
    uint64_t size;

    /* A vIOMMU translating this device: follow the guest's mappings. */
    if (memory_region_is_iommu(section->mr)) {
        peer_mmio_iommu_add(peer, section);
        return;
    }

    /* RAM is announced, with its fd, by the VFIO listener. */
    if (memory_region_is_ram(section->mr)) {
        return;
    }

    iova = section->offset_within_address_space;
    size = int128_get64(section->size);

    /* Sizing a 64-bit BAR can map it far outside any address width. */
    if (!size || (iova & (1ULL << 63))) {
        return;
    }

    owner = peer_mmio_bar_owner(peer, section);
    if (owner) {
        peer_mmio_announce(peer, owner, iova, size, section->readonly, NULL);
    }
}

static void peer_mmio_region_del(MemoryListener *listener,
                                 MemoryRegionSection *section)
{
    VFIOUserPeerMMIO *peer = container_of(listener, VFIOUserPeerMMIO, listener);
    VFIOUserPeerRange *range;

    if (memory_region_is_iommu(section->mr)) {
        peer_mmio_iommu_del(peer, section);
        return;
    }

    /*
     * Look the range up instead of re-deriving it from the BAR: by now the
     * device's BAR state may already describe the new placement.
     */
    range = peer_mmio_find(peer, section->offset_within_address_space,
                           int128_get64(section->size));
    if (range && !range->origin) {
        peer_mmio_withdraw(peer, range);
    }
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
