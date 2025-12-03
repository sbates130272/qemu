/*
 * GPU-based NVMe Write Test using GPU VRAM (P2P DMA)
 * 
 * This variant uses GPU device memory (VRAM) instead of host memory,
 * enabling true GPU→NVMe peer-to-peer DMA.
 * 
 * Compile:
 *   /opt/rocm/bin/hipcc -o test-gpu-nvme-write-vram \
 *       test-gpu-nvme-write-vram.cpp \
 *       -I/usr/include/libdrm -ldrm -ldrm_amdgpu
 *
 * Run (as root):
 *   sudo HSA_FORCE_FINE_GRAIN_PCIE=1 ./test-gpu-nvme-write-vram \
 *       /dev/nvme1 0 8
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdlib.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>
#include <linux/nvme_ioctl.h>

#define NVME_PAGE_SIZE  4096
#define QUEUE_SIZE      64

/* GPU BAR address lookup */
static int get_gpu_bar_address(uint64_t *bar_addr, uint64_t *bar_size)
{
    FILE *f;
    char line[256];
    int found = 0;
    
    /* Find GPU in lspci output */
    f = popen("lspci -v -d 1002: 2>/dev/null", "r");
    if (!f) return -1;
    
    while (fgets(line, sizeof(line), f)) {
        /* Look for VRAM BAR (usually 64-bit prefetchable) */
        if (strstr(line, "Memory at") && 
            strstr(line, "64-bit") && 
            strstr(line, "prefetchable")) {
            unsigned long long addr, size_end;
            if (sscanf(line, " Memory at %llx-%llx", &addr, &size_end) == 2) {
                *bar_addr = addr;
                *bar_size = size_end - addr + 1;
                found = 1;
                break;
            }
        }
    }
    pclose(f);
    
    return found ? 0 : -1;
}

/* Get GPU memory allocation info from AMDGPU */
static int get_vram_physical_offset(void *vram_ptr, uint64_t *offset)
{
    /* For now, return error - this needs proper AMDGPU ioctl */
    fprintf(stderr, "ERROR: VRAM physical address lookup not implemented\n");
    fprintf(stderr, "Note: This requires:\n");
    fprintf(stderr, "  1. AMDGPU GEM handle for the allocation\n");
    fprintf(stderr, "  2. DRM_IOCTL_AMDGPU_GEM_MMAP to get BAR offset\n");
    fprintf(stderr, "  3. GPU BAR base address from PCI config\n");
    return -1;
}

int main(int argc, char **argv)
{
    void *vram_buffer = NULL;
    uint64_t gpu_bar_addr = 0, gpu_bar_size = 0;
    uint64_t vram_offset = 0, data_phys = 0;
    
    printf("=================================================\n");
    printf("GPU-based NVMe Write Test (GPU VRAM P2P)\n");
    printf("=================================================\n\n");
    
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <nvme_device> <lba> [qid]\n", argv[0]);
        return 1;
    }
    
    printf("Step 1: Discovering GPU BAR...\n");
    if (get_gpu_bar_address(&gpu_bar_addr, &gpu_bar_size) < 0) {
        fprintf(stderr, "ERROR: Could not find GPU VRAM BAR\n");
        return 1;
    }
    printf("  GPU BAR: 0x%lx (size: 0x%lx)\n\n", gpu_bar_addr, gpu_bar_size);
    
    printf("Step 2: Allocating 4KiB buffer in GPU VRAM...\n");
    if (hipMalloc(&vram_buffer, NVME_PAGE_SIZE) != hipSuccess) {
        fprintf(stderr, "ERROR: hipMalloc failed\n");
        return 1;
    }
    printf("  VRAM buffer: %p\n", vram_buffer);
    
    /* Get physical address of VRAM allocation */
    if (get_vram_physical_offset(vram_buffer, &vram_offset) < 0) {
        fprintf(stderr, "\nTo enable GPU VRAM P2P, you need:\n");
        fprintf(stderr, "  1. P2PDMA kernel support\n");
        fprintf(stderr, "  2. AMDGPU BAR offset lookup\n");
        fprintf(stderr, "  3. IOMMU configuration for P2P\n\n");
        fprintf(stderr, "Fallback: Use hipHostMalloc (current working version)\n");
        hipFree(vram_buffer);
        return 1;
    }
    
    data_phys = gpu_bar_addr + vram_offset;
    printf("  VRAM offset in BAR: 0x%lx\n", vram_offset);
    printf("  Physical address for NVMe: 0x%lx\n", data_phys);
    printf("  ✅ NVMe can DMA directly from GPU VRAM\n\n");
    
    /* Rest of the test would be same as current version,
     * but using vram_buffer and data_phys
     */
    
    printf("Note: Full implementation requires AMDGPU DRM integration\n");
    printf("See AMDGPU_GEM_OP_GET_GEM_CREATE_INFO for getting BAR offset\n");
    
    hipFree(vram_buffer);
    return 0;
}

