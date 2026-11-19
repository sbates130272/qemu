/*
 * vfio-user specific definitions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_VFIO_USER_CONTAINER_H
#define HW_VFIO_USER_CONTAINER_H


#include "hw/vfio/vfio-container.h"
#include "hw/vfio-user/proxy.h"

typedef struct VFIOUserPeerMMIO VFIOUserPeerMMIO;
typedef struct VFIOUserDMARange VFIOUserDMARange;

/* MMU container sub-class for vfio-user. */
struct VFIOUserContainer {
    VFIOContainer parent_obj;

    VFIOUserProxy *proxy;

    /* Non-NULL only when the device has x-peer-mmio=on. */
    VFIOUserPeerMMIO *peer_mmio;

    /*
     * What the server was sent with DMA_MAP and not yet told to unmap: a
     * DMA_UNMAP must name a mapping exactly, but the requests to unmap come
     * from the memory core and from a vIOMMU as arbitrary ranges.
     */
    QLIST_HEAD(, VFIOUserDMARange) dma_ranges;
};

OBJECT_DECLARE_SIMPLE_TYPE(VFIOUserContainer, VFIO_IOMMU_USER);

int vfio_user_container_dma_map(VFIOUserContainer *container, hwaddr iova,
                                uint64_t size, int fd, uint64_t offset,
                                bool readonly);
int vfio_user_container_dma_unmap(VFIOUserContainer *container, hwaddr iova,
                                  uint64_t size);

/*
 * x-peer-mmio: announce other PCI devices' BARs to the server as DMA regions
 * it can only reach through DMA_READ/DMA_WRITE messages.
 */
void vfio_user_peer_mmio_register(VFIOUserContainer *container,
                                  AddressSpace *as, DeviceState *self);
void vfio_user_peer_mmio_unregister(VFIOUserContainer *container);

#endif /* HW_VFIO_USER_CONTAINER_H */
