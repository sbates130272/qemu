/*
 * Test amdgpu GEM_USERPTR to register /dev/mem mapping with GPU
 * 
 * Uses DRM_IOCTL_AMDGPU_GEM_USERPTR to register the shadow buffer
 * (/dev/mem mapping at GPA 0x80000000) with the amdgpu driver.
 *
 * This should allow GPU kernels to write to that physical address!
 *
 * Compile: hipcc -o test-amdgpu-userptr test-amdgpu-userptr.cpp -ldrm -ldrm_amdgpu
 * Run: sudo ./test-amdgpu-userptr
 */

#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>
#include <xf86drm.h>

__global__ void gpu_write_marker(uint32_t *ptr, uint32_t value)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        *ptr = value;
        __threadfence_system();
        printf("[GPU] Wrote 0x%08x to %p\n", value, ptr);
    }
}

int main()
{
    void *shadow_cpu;
    int mem_fd, drm_fd;
    uint64_t shadow_gpa = 0x80000000;
    uint32_t shadow_size = 8192;
    
    printf("=================================================\n");
    printf("Test amdgpu GEM_USERPTR with /dev/mem mapping\n");
    printf("=================================================\n\n");
    
    /* Step 1: Map shadow buffer via /dev/mem */
    printf("Step 1: Map shadow buffer at GPA 0x%llx...\n",
           (unsigned long long)shadow_gpa);
    mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    shadow_cpu = mmap(NULL, shadow_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, mem_fd, shadow_gpa);
    close(mem_fd);
    
    if (shadow_cpu == MAP_FAILED) {
        perror("mmap /dev/mem");
        return 1;
    }
    
    printf("  CPU ptr: %p\n", shadow_cpu);
    
    /* Clear it */
    memset(shadow_cpu, 0, shadow_size);
    printf("  Cleared memory\n\n");
    
    /* Step 2: Open amdgpu DRM device */
    printf("Step 2: Open amdgpu DRM device...\n");
    drm_fd = open("/dev/dri/renderD128", O_RDWR);
    if (drm_fd < 0) {
        perror("open /dev/dri/renderD128");
        munmap(shadow_cpu, shadow_size);
        return 1;
    }
    printf("  DRM fd: %d\n\n", drm_fd);
    
    /* Step 3: Register userptr with amdgpu */
    printf("Step 3: Register userptr with amdgpu driver...\n");
    struct drm_amdgpu_gem_userptr userptr_args = {0};
    userptr_args.addr = (uint64_t)shadow_cpu;
    userptr_args.size = shadow_size;
    userptr_args.flags = AMDGPU_GEM_USERPTR_REGISTER;
    
    int ret = drmIoctl(drm_fd, DRM_IOCTL_AMDGPU_GEM_USERPTR, &userptr_args);
    if (ret) {
        perror("DRM_IOCTL_AMDGPU_GEM_USERPTR");
        printf("  ❌ Failed to register userptr\n");
        printf("  This may require specific kernel/driver support\n\n");
        close(drm_fd);
        munmap(shadow_cpu, shadow_size);
        return 1;
    }
    
    printf("  ✅ Userptr registered!\n");
    printf("  GEM handle: %u\n", userptr_args.handle);
    printf("  Addr: 0x%llx\n", (unsigned long long)userptr_args.addr);
    printf("  Size: %llu\n\n", (unsigned long long)userptr_args.size);
    
    /* Step 4: Now try HIP operations with this memory */
    printf("Step 4: Test GPU write via HIP...\n");
    
    /* HIP might need special handling to use this GEM handle */
    /* For now, test if hipHostRegister works better after GEM_USERPTR */
    hipError_t err = hipHostRegister(shadow_cpu, shadow_size,
                                      hipHostRegisterMapped);
    if (err != hipSuccess) {
        printf("  ⚠️  hipHostRegister still fails: %s\n", 
               hipGetErrorString(err));
        printf("  Trying direct GPU write to CPU ptr...\n\n");
    } else {
        printf("  ✅ hipHostRegister succeeded after GEM_USERPTR!\n\n");
    }
    
    void *device_ptr = shadow_cpu; /* Or get from hipHostGetDevicePointer */
    if (err == hipSuccess) {
        hipHostGetDevicePointer(&device_ptr, shadow_cpu, 0);
    }
    
    /* Launch GPU kernel */
    printf("Step 5: GPU writes 0xDEADBEEF...\n");
    hipLaunchKernelGGL(gpu_write_marker, dim3(1), dim3(1), 0, 0,
                       (uint32_t*)device_ptr, 0xDEADBEEF);
    hipError_t sync_err = hipDeviceSynchronize();
    if (sync_err != hipSuccess) {
        printf("  Kernel error: %s\n", hipGetErrorString(sync_err));
    }
    printf("\n");
    
    /* Step 6: Check results */
    printf("Step 6: Check where GPU wrote...\n");
    printf("  Value at CPU ptr: 0x%08x\n", *(uint32_t*)shadow_cpu);
    
    /* Re-read from /dev/mem */
    mem_fd = open("/dev/mem", O_RDONLY | O_SYNC);
    void *check = mmap(NULL, 4, PROT_READ, MAP_SHARED, mem_fd, shadow_gpa);
    printf("  Value at GPA 0x%llx: 0x%08x\n",
           (unsigned long long)shadow_gpa, *(uint32_t*)check);
    munmap(check, 4);
    close(mem_fd);
    printf("\n");
    
    /* Summary */
    printf("=================================================\n");
    printf("Summary\n");
    printf("=================================================\n");
    if (*(uint32_t*)shadow_cpu == 0xDEADBEEF) {
        printf("🎉 SUCCESS!\n");
        printf("   GPU write visible via CPU ptr!\n");
        mem_fd = open("/dev/mem", O_RDONLY | O_SYNC);
        check = mmap(NULL, 4, PROT_READ, MAP_SHARED, mem_fd, shadow_gpa);
        if (*(uint32_t*)check == 0xDEADBEEF) {
            printf("   ✅ GPU write reached GPA 0x%llx!\n",
                   (unsigned long long)shadow_gpa);
            printf("   🚀 amdgpu GEM_USERPTR WORKS!\n");
        }
        munmap(check, 4);
        close(mem_fd);
    } else {
        printf("❌ GPU write did not reach shadow buffer\n");
    }
    printf("=================================================\n");
    
    /* Cleanup */
    if (err == hipSuccess) {
        hipHostUnregister(shadow_cpu);
    }
    
    /* Unregister GEM object */
    struct drm_gem_close close_args = {0};
    close_args.handle = userptr_args.handle;
    drmIoctl(drm_fd, DRM_IOCTL_GEM_CLOSE, &close_args);
    
    close(drm_fd);
    munmap(shadow_cpu, shadow_size);
    
    return 0;
}

