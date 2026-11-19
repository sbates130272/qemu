/*
 * Container for vfio-user IOMMU type: rather than communicating with the kernel
 * vfio driver, we communicate over a socket to a server using the vfio-user
 * protocol.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <sys/ioctl.h>
#include <linux/vfio.h>

#include "hw/vfio-user/container.h"
#include "hw/vfio-user/device.h"
#include "hw/vfio-user/trace.h"
#include "hw/vfio/vfio-device.h"
#include "hw/vfio/vfio-listener.h"
#include "system/ramblock.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

/*
 * When DMA space is the physical address space, the region add/del listeners
 * will fire during memory update transactions.  These depend on BQL being held,
 * so do any resulting map/demap ops async while keeping BQL.
 */
static void vfio_user_listener_begin(VFIOContainer *bcontainer)
{
    VFIOUserContainer *container = VFIO_IOMMU_USER(bcontainer);

    container->proxy->async_ops = true;
}

static void vfio_user_listener_commit(VFIOContainer *bcontainer)
{
    VFIOUserContainer *container = VFIO_IOMMU_USER(bcontainer);

    /* wait here for any async requests sent during the transaction */
    container->proxy->async_ops = false;
    vfio_user_wait_reqs(container->proxy);
}

struct VFIOUserDMARange {
    QLIST_ENTRY(VFIOUserDMARange) next;
    hwaddr iova;
    uint64_t size;
    int fd;             /* -1: reached by DMA_READ/DMA_WRITE only; not owned */
    uint64_t offset;    /* of iova within fd */
    bool readonly;
};

static void vfio_user_track_dma(VFIOUserContainer *container, hwaddr iova,
                                uint64_t size, int fd, uint64_t offset,
                                bool readonly)
{
    VFIOUserDMARange *r;

    /* The server accepts the same mapping twice; keep one record of it. */
    QLIST_FOREACH(r, &container->dma_ranges, next) {
        if (r->iova == iova && r->size == size) {
            r->fd = fd;
            r->offset = offset;
            r->readonly = readonly;
            return;
        }
    }

    r = g_new0(VFIOUserDMARange, 1);
    r->iova = iova;
    r->size = size;
    r->fd = fd;
    r->offset = offset;
    r->readonly = readonly;
    QLIST_INSERT_HEAD(&container->dma_ranges, r, next);
}

/* Send one DMA_UNMAP, which must name a mapping the server holds exactly. */
static int vfio_user_send_dma_unmap(VFIOUserContainer *container,
                                    hwaddr iova, uint64_t size)
{
    Error *local_err = NULL;
    int ret = 0;

    VFIOUserDMAUnmap *msgp = g_malloc(sizeof(*msgp));

    vfio_user_request_msg(&msgp->hdr, VFIO_USER_DMA_UNMAP, sizeof(*msgp), 0);
    msgp->argsz = sizeof(struct vfio_iommu_type1_dma_unmap);
    msgp->flags = 0;
    msgp->iova = iova;
    msgp->size = size;
    trace_vfio_user_dma_unmap(msgp->iova, msgp->size, msgp->flags,
                              container->proxy->async_ops);

    if (container->proxy->async_ops) {
        if (!vfio_user_send_nowait(container->proxy, &msgp->hdr, NULL,
                              0, &local_err)) {
            error_report_err(local_err);
            ret = -EFAULT;
        }
    } else {
        if (!vfio_user_send_wait(container->proxy, &msgp->hdr, NULL,
                                 0, &local_err)) {
                error_report_err(local_err);
                ret = -EFAULT;
        }

        if (msgp->hdr.flags & VFIO_USER_ERROR) {
            ret = -msgp->hdr.error_reply;
        }

        g_free(msgp);
    }

    return ret;
}

/*
 * Send a DMA_MAP for [iova, iova + size).  With an fd the server may map it
 * and access it directly at offset; with fd == -1 it can only reach the range
 * through DMA_READ/DMA_WRITE messages, which QEMU services.
 */
int vfio_user_container_dma_map(VFIOUserContainer *container, hwaddr iova,
                                uint64_t size, int fd, uint64_t offset,
                                bool readonly)
{
    Error *local_err = NULL;
    int ret = 0;

    VFIOUserFDs *fds = NULL;
    VFIOUserDMAMap *msgp = g_malloc0(sizeof(*msgp));

    vfio_user_request_msg(&msgp->hdr, VFIO_USER_DMA_MAP, sizeof(*msgp), 0);
    msgp->argsz = sizeof(struct vfio_iommu_type1_dma_map);
    msgp->flags = VFIO_DMA_MAP_FLAG_READ;
    msgp->offset = offset;
    msgp->iova = iova;
    msgp->size = size;

    if (!readonly) {
        msgp->flags |= VFIO_DMA_MAP_FLAG_WRITE;
    }

    trace_vfio_user_dma_map(msgp->iova, msgp->size, msgp->offset, msgp->flags,
                            container->proxy->async_ops);

    /*
     * The async_ops case sends without blocking. They're later waited for in
     * vfio_send_wait_reqs.
     */
    if (container->proxy->async_ops) {
        /* can't use auto variable since we don't block */
        if (fd != -1) {
            fds = vfio_user_getfds(1);
            fds->send_fds = 1;
            fds->fds[0] = fd;
        }

        if (!vfio_user_send_nowait(container->proxy, &msgp->hdr, fds,
                              0, &local_err)) {
            error_report_err(local_err);
            ret = -EFAULT;
        }
    } else {
        VFIOUserFDs local_fds = { 1, 0, &fd };

        fds = fd != -1 ? &local_fds : NULL;

        if (!vfio_user_send_wait(container->proxy, &msgp->hdr, fds,
                                 0, &local_err)) {
                error_report_err(local_err);
                ret = -EFAULT;
        }

        if (msgp->hdr.flags & VFIO_USER_ERROR) {
            ret = -msgp->hdr.error_reply;
        }

        g_free(msgp);
    }

    if (ret == 0) {
        vfio_user_track_dma(container, iova, size, fd, offset, readonly);
    }

    return ret;
}

static int vfio_user_dma_map(const VFIOContainer *bcontainer, hwaddr iova,
                             uint64_t size, void *vaddr, bool readonly,
                             MemoryRegion *mrp)
{
    VFIOUserContainer *container = VFIO_IOMMU_USER(bcontainer);
    int fd = memory_region_get_fd(mrp);
    uint64_t offset = 0;

    /*
     * vaddr enters as a QEMU process address; make it either a file offset
     * for mapped areas or leave as 0.
     */
    if (fd != -1) {
        offset = qemu_ram_block_host_offset(mrp->ram_block, vaddr);
    }

    return vfio_user_container_dma_map(container, iova, size, fd, offset,
                                       readonly);
}

/*
 * Unmap [iova, iova + size), or everything when @unmap_all.
 *
 * The memory core asks for the ranges it added, but a vIOMMU asks for whatever
 * the guest changed, including its whole address space in power-of-two chunks
 * when a domain is dropped.  A server removes only a mapping it holds exactly
 * (the spec says so), so a request that does not match one is answered with
 * ENOENT and the mapping stays: the server keeps reaching memory the guest has
 * unmapped, and a later map at that address with a different backing is
 * refused.  So turn the request into exact unmaps of the ranges sent, which
 * for a range never sent is nothing, as for kernel VFIO.  A request that cuts
 * through a mapping can only remove all of it; map the rest back.
 */
static int vfio_user_dma_unmap(const VFIOContainer *bcontainer,
                               hwaddr iova, uint64_t size,
                               IOMMUTLBEntry *iotlb, bool unmap_all)
{
    VFIOUserContainer *container = VFIO_IOMMU_USER(bcontainer);
    VFIOUserDMARange *r, *tmp;
    GArray *rest = g_array_new(false, false, sizeof(VFIOUserDMARange));
    hwaddr end = iova + size;
    int ret = 0;
    guint i;

    QLIST_FOREACH_SAFE(r, &container->dma_ranges, next, tmp) {
        hwaddr r_end = r->iova + r->size;
        int err;

        if (!unmap_all && (r_end <= iova || r->iova >= end)) {
            continue;
        }

        trace_vfio_user_dma_unmap_range(r->iova, r->size, iova, size);
        err = vfio_user_send_dma_unmap(container, r->iova, r->size);
        if (err && !ret) {
            ret = err;
        }
        QLIST_REMOVE(r, next);

        if (!unmap_all) {
            VFIOUserDMARange keep;

            if (r->iova < iova) {
                keep = *r;
                keep.size = iova - r->iova;
                g_array_append_val(rest, keep);
            }
            if (r_end > end) {
                keep = *r;
                keep.iova = end;
                keep.size = r_end - end;
                keep.offset = r->offset + (end - r->iova);
                g_array_append_val(rest, keep);
            }
        }
        g_free(r);
    }

    for (i = 0; i < rest->len; i++) {
        VFIOUserDMARange *keep = &g_array_index(rest, VFIOUserDMARange, i);

        if (vfio_user_container_dma_map(container, keep->iova, keep->size,
                                        keep->fd, keep->offset,
                                        keep->readonly)) {
            error_report("vfio-user: cannot map back 0x%"PRIx64" size "
                         "0x%"PRIx64" after an unmap of part of it",
                         keep->iova, keep->size);
        }
    }
    g_array_free(rest, true);

    return ret;
}

int vfio_user_container_dma_unmap(VFIOUserContainer *container, hwaddr iova,
                                  uint64_t size)
{
    return vfio_user_dma_unmap(VFIO_IOMMU(container), iova, size, NULL, false);
}

static int
vfio_user_set_dirty_page_tracking(const VFIOContainer *bcontainer,
                                    bool start, Error **errp)
{
    error_setg_errno(errp, ENOTSUP, "Not supported");
    return -ENOTSUP;
}

static int vfio_user_query_dirty_bitmap(const VFIOContainer *bcontainer,
                                        VFIOBitmap *vbmap, hwaddr iova,
                                        hwaddr size, uint64_t backend_flag,
                                        Error **errp)
{
    error_setg_errno(errp, ENOTSUP, "Not supported");
    return -ENOTSUP;
}

static bool vfio_user_setup(VFIOContainer *bcontainer, Error **errp)
{
    VFIOUserContainer *container = VFIO_IOMMU_USER(bcontainer);

    assert(container->proxy->dma_pgsizes != 0);
    bcontainer->pgsizes = container->proxy->dma_pgsizes;
    bcontainer->dma_max_mappings = container->proxy->max_dma;

    /* No live migration support yet. */
    bcontainer->dirty_pages_supported = false;
    bcontainer->max_dirty_bitmap_size = container->proxy->max_bitmap;
    bcontainer->dirty_pgsizes = container->proxy->migr_pgsize;

    return true;
}

static VFIOUserContainer *vfio_user_create_container(VFIODevice *vbasedev,
                                                     Error **errp)
{
    VFIOUserContainer *container;

    container = VFIO_IOMMU_USER(object_new(TYPE_VFIO_IOMMU_USER));
    container->proxy = vbasedev->proxy;
    return container;
}

/*
 * Try to mirror vfio_container_connect() as much as possible.
 */
static VFIOUserContainer *
vfio_user_container_connect(AddressSpace *as, VFIODevice *vbasedev,
                            Error **errp)
{
    VFIOContainer *bcontainer;
    VFIOUserContainer *container;
    VFIOAddressSpace *space;
    VFIOIOMMUClass *vioc;
    int ret;

    space = vfio_address_space_get(as);

    container = vfio_user_create_container(vbasedev, errp);
    if (!container) {
        goto put_space_exit;
    }

    bcontainer = VFIO_IOMMU(container);

    ret = ram_block_uncoordinated_discard_disable(true);
    if (ret) {
        error_setg_errno(errp, -ret, "Cannot set discarding of RAM broken");
        goto free_container_exit;
    }

    vioc = VFIO_IOMMU_GET_CLASS(bcontainer);
    assert(vioc->setup);

    if (!vioc->setup(bcontainer, errp)) {
        goto enable_discards_exit;
    }

    vfio_address_space_insert(space, bcontainer);

    if (!vfio_listener_register(bcontainer, errp)) {
        goto listener_release_exit;
    }

    if (vbasedev->proxy->flags & VFIO_PROXY_PEER_MMIO) {
        vfio_user_peer_mmio_register(container, as, vbasedev->dev);
    }

    bcontainer->initialized = true;

    return container;

listener_release_exit:
    vfio_listener_unregister(bcontainer);
    if (vioc->release) {
        vioc->release(bcontainer);
    }

enable_discards_exit:
    ram_block_uncoordinated_discard_disable(false);

free_container_exit:
    object_unref(container);

put_space_exit:
    vfio_address_space_put(space);

    return NULL;
}

static void vfio_user_container_disconnect(VFIOUserContainer *container)
{
    VFIOContainer *bcontainer = VFIO_IOMMU(container);
    VFIOIOMMUClass *vioc = VFIO_IOMMU_GET_CLASS(bcontainer);
    VFIOAddressSpace *space = bcontainer->space;

    ram_block_uncoordinated_discard_disable(false);

    vfio_user_peer_mmio_unregister(container);
    while (!QLIST_EMPTY(&container->dma_ranges)) {
        VFIOUserDMARange *r = QLIST_FIRST(&container->dma_ranges);

        QLIST_REMOVE(r, next);
        g_free(r);
    }
    vfio_listener_unregister(bcontainer);
    if (vioc->release) {
        vioc->release(bcontainer);
    }

    object_unref(container);

    vfio_address_space_put(space);
}

static bool vfio_user_device_get(VFIOUserContainer *container,
                                 VFIODevice *vbasedev, Error **errp)
{
    struct vfio_device_info info = { .argsz = sizeof(info) };


    if (!vfio_user_get_device_info(vbasedev->proxy, &info, errp)) {
        return false;
    }

    vbasedev->fd = -1;

    vfio_device_prepare(vbasedev, VFIO_IOMMU(container), &info);

    return true;
}

/*
 * vfio_user_device_attach: attach a device to a new container.
 */
static bool vfio_user_device_attach(const char *name, VFIODevice *vbasedev,
                                    AddressSpace *as, Error **errp)
{
    VFIOUserContainer *container;

    container = vfio_user_container_connect(as, vbasedev, errp);
    if (container == NULL) {
        error_prepend(errp, "failed to connect proxy");
        return false;
    }

    if (!vfio_user_device_get(container, vbasedev, errp)) {
        vfio_user_container_disconnect(container);
        return false;
    }

    return true;
}

static void vfio_user_device_detach(VFIODevice *vbasedev)
{
    VFIOUserContainer *container = VFIO_IOMMU_USER(vbasedev->bcontainer);

    vfio_device_unprepare(vbasedev);

    vfio_user_container_disconnect(container);
}

static int vfio_user_pci_hot_reset(VFIODevice *vbasedev, bool single)
{
    /* ->needs_reset is always false for vfio-user. */
    return 0;
}

static void vfio_iommu_user_class_init(ObjectClass *klass, const void *data)
{
    VFIOIOMMUClass *vioc = VFIO_IOMMU_CLASS(klass);

    vioc->setup = vfio_user_setup;
    vioc->listener_begin = vfio_user_listener_begin,
    vioc->listener_commit = vfio_user_listener_commit,
    vioc->dma_map = vfio_user_dma_map;
    vioc->dma_unmap = vfio_user_dma_unmap;
    vioc->attach_device = vfio_user_device_attach;
    vioc->detach_device = vfio_user_device_detach;
    vioc->set_dirty_page_tracking = vfio_user_set_dirty_page_tracking;
    vioc->query_dirty_bitmap = vfio_user_query_dirty_bitmap;
    vioc->pci_hot_reset = vfio_user_pci_hot_reset;
};

static const TypeInfo types[] = {
    {
        .name = TYPE_VFIO_IOMMU_USER,
        .parent = TYPE_VFIO_IOMMU,
        .instance_size = sizeof(VFIOUserContainer),
        .class_init = vfio_iommu_user_class_init,
    },
};

DEFINE_TYPES(types)
