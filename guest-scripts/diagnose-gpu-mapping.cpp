#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>
#include <sys/ioctl.h>

#define PAGE_SIZE 4096
#define TARGET_GPA 0x80000000ULL

uint64_t virt_to_phys(void *virt_addr) {
    uint64_t value;
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) return 0;
    
    uint64_t offset = ((uint64_t)virt_addr / PAGE_SIZE) * sizeof(uint64_t);
    if (lseek(pagemap_fd, offset, SEEK_SET) != (off_t)offset) {
        close(pagemap_fd);
        return 0;
    }
    
    if (read(pagemap_fd, &value, sizeof(value)) != sizeof(value)) {
        close(pagemap_fd);
        return 0;
    }
    close(pagemap_fd);
    
    if (!(value & (1ULL << 63))) return 0;
    
    uint64_t pfn = value & ((1ULL << 55) - 1);
    uint64_t page_offset = (uint64_t)virt_addr & (PAGE_SIZE - 1);
    return (pfn * PAGE_SIZE) + page_offset;
}

__global__ void write_and_report(uint64_t *addr_out, uint32_t *value_out, 
                                  uint64_t *ptr) {
    *addr_out = (uint64_t)ptr;  // Report what address GPU sees
    *ptr = 0xDEADBEEF;          // Write the magic value
    *value_out = *ptr;          // Read it back
}

int main() {
    printf("=================================================\n");
    printf("Diagnose GPU Address Mapping\n");
    printf("=================================================\n\n");
    
    // Map target GPA via /dev/mem
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    void *shadow_cpu = mmap(NULL, 8192, PROT_READ | PROT_WRITE, 
                             MAP_SHARED, mem_fd, TARGET_GPA);
    close(mem_fd);
    
    if (shadow_cpu == MAP_FAILED) {
        perror("mmap /dev/mem");
        return 1;
    }
    
    // Force pages to be resident by touching them
    ::memset(shadow_cpu, 0, 8192);
    volatile uint32_t *test_ptr = (uint32_t*)shadow_cpu;
    *test_ptr = 0x12345678;  // Write to force page fault
    uint32_t readback = *test_ptr;  // Read back
    
    printf("Step 1: CPU mapping\n");
    printf("  Target GPA:    0x%llx\n", TARGET_GPA);
    printf("  CPU virt addr: %p\n", shadow_cpu);
    printf("  Test write/read: 0x%x (expected 0x12345678)\n", readback);
    printf("  CPU->phys:     0x%llx\n\n", virt_to_phys(shadow_cpu));
    
    // Register with amdgpu
    int drm_fd = open("/dev/dri/renderD128", O_RDWR);
    if (drm_fd < 0) {
        perror("open DRM");
        return 1;
    }
    
    struct drm_amdgpu_gem_userptr userptr = {0};
    userptr.addr = (uint64_t)shadow_cpu;
    userptr.size = 8192;
    userptr.flags = AMDGPU_GEM_USERPTR_REGISTER;
    
    if (ioctl(drm_fd, DRM_IOCTL_AMDGPU_GEM_USERPTR, &userptr) < 0) {
        perror("GEM_USERPTR");
        close(drm_fd);
        return 1;
    }
    
    printf("Step 2: GEM_USERPTR registration\n");
    printf("  ✅ GEM_USERPTR succeeded!\n");
    printf("  GEM handle: %u\n", userptr.handle);
    printf("  Flags: 0x%x\n\n", userptr.flags);
    
    // Register with HIP - try different flag combinations
    printf("Step 3: HIP registration attempts\n");
    
    hipError_t err = hipHostRegister(shadow_cpu, 8192, hipHostRegisterMapped);
    if (err != hipSuccess) {
        printf("  ❌ hipHostRegisterMapped failed: %s\n", hipGetErrorString(err));
        
        // Try without any flags
        err = hipHostRegister(shadow_cpu, 8192, 0);
        if (err != hipSuccess) {
            printf("  ❌ hipHostRegister(0) failed: %s\n", hipGetErrorString(err));
            close(drm_fd);
            return 1;
        } else {
            printf("  ✅ hipHostRegister(0) succeeded!\n");
        }
    } else {
        printf("  ✅ hipHostRegisterMapped succeeded!\n");
    }
    
    // Get device pointer
    void *shadow_gpu = NULL;
    err = hipHostGetDevicePointer(&shadow_gpu, shadow_cpu, 0);
    if (err != hipSuccess) {
        printf("❌ hipHostGetDevicePointer failed: %s\n", hipGetErrorString(err));
        hipHostUnregister(shadow_cpu);
        close(drm_fd);
        return 1;
    }
    
    printf("\nStep 4: HIP device pointer\n");
    printf("  CPU virt addr: %p\n", shadow_cpu);
    printf("  GPU virt addr: %p\n", shadow_gpu);
    printf("  Match: %s\n\n", (shadow_cpu == shadow_gpu) ? "YES" : "NO");
    
    // Allocate result buffers
    uint64_t *d_addr, *d_value;
    hipMalloc(&d_addr, sizeof(uint64_t));
    hipMalloc(&d_value, sizeof(uint32_t));
    
    printf("Step 5: GPU kernel execution\n");
    hipLaunchKernelGGL(write_and_report, dim3(1), dim3(1), 0, 0,
                       d_addr, (uint32_t*)d_value, (uint64_t*)shadow_gpu);
    hipDeviceSynchronize();
    
    uint64_t gpu_saw_addr = 0;
    uint32_t gpu_read_value = 0;
    hipMemcpy(&gpu_saw_addr, d_addr, sizeof(uint64_t), hipMemcpyDeviceToHost);
    hipMemcpy(&gpu_read_value, d_value, sizeof(uint32_t), hipMemcpyDeviceToHost);
    
    printf("  GPU saw address:     %p\n", (void*)gpu_saw_addr);
    printf("  GPU read back value: 0x%x\n\n", gpu_read_value);
    
    printf("Step 6: Verify writes\n");
    uint32_t cpu_value = *(uint32_t*)shadow_cpu;
    printf("  Value at CPU ptr:    0x%x\n", cpu_value);
    printf("  Value read by GPU:   0x%x\n", gpu_read_value);
    printf("  Expected:            0xDEADBEEF\n\n");
    
    printf("=================================================\n");
    if (cpu_value == 0xDEADBEEF && gpu_read_value == 0xDEADBEEF) {
        printf("✅ SUCCESS! GPU wrote to the correct location!\n");
        printf("   Physical address: 0x%llx\n", virt_to_phys(shadow_cpu));
    } else if (gpu_read_value == 0xDEADBEEF && cpu_value == 0) {
        printf("⚠️  GPU wrote somewhere, but NOT to GPA 0x%llx\n", TARGET_GPA);
        printf("   GPU is using its own physical mapping\n");
    } else {
        printf("❌ GPU kernel did not execute or failed\n");
    }
    printf("=================================================\n");
    
    hipFree(d_addr);
    hipFree(d_value);
    hipHostUnregister(shadow_cpu);
    close(drm_fd);
    munmap(shadow_cpu, 8192);
    
    return 0;
}
