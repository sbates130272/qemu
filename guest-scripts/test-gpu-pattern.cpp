#include <hip/hip_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <string.h>
#include <drm/drm.h>
#include <drm/amdgpu_drm.h>

#define TARGET_GPA 0x80000000ULL

__global__ void write_pattern(uint32_t *ptr) {
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        // Write distinct pattern at different offsets
        ptr[0] = 0x11111111;  // Offset 0
        ptr[1] = 0x22222222;  // Offset 4
        ptr[2] = 0x33333333;  // Offset 8
        ptr[3] = 0x44444444;  // Offset 12
        ptr[4] = 0x55555555;  // Offset 16
        ptr[5] = 0x66666666;  // Offset 20
        ptr[6] = 0x77777777;  // Offset 24
        ptr[7] = 0x88888888;  // Offset 28
        __threadfence_system();
    }
}

int main() {
    printf("=== GPU Pattern Write Test ===\n\n");
    
    // Map GPA 0x80000000
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    void *cpu_ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_SHARED, mem_fd, TARGET_GPA);
    if (cpu_ptr == MAP_FAILED) {
        perror("mmap");
        close(mem_fd);
        return 1;
    }
    
    // Clear memory
    ::memset(cpu_ptr, 0, 64);
    printf("Step 1: Cleared GPA 0x%llx\n\n", TARGET_GPA);
    
    // Register with amdgpu
    int drm_fd = open("/dev/dri/renderD128", O_RDWR);
    if (drm_fd < 0) {
        perror("open DRM");
        munmap(cpu_ptr, 4096);
        close(mem_fd);
        return 1;
    }
    
    struct drm_amdgpu_gem_userptr userptr = {0};
    userptr.addr = (uint64_t)cpu_ptr;
    userptr.size = 4096;
    userptr.flags = AMDGPU_GEM_USERPTR_REGISTER;
    
    if (ioctl(drm_fd, DRM_IOCTL_AMDGPU_GEM_USERPTR, &userptr) < 0) {
        perror("GEM_USERPTR");
        close(drm_fd);
        munmap(cpu_ptr, 4096);
        close(mem_fd);
        return 1;
    }
    printf("Step 2: GEM_USERPTR registered\n\n");
    
    // Register with HIP
    hipError_t err = hipHostRegister(cpu_ptr, 4096, hipHostRegisterMapped);
    if (err != hipSuccess) {
        fprintf(stderr, "hipHostRegister failed: %s\n", hipGetErrorString(err));
        close(drm_fd);
        munmap(cpu_ptr, 4096);
        close(mem_fd);
        return 1;
    }
    
    void *gpu_ptr = NULL;
    err = hipHostGetDevicePointer(&gpu_ptr, cpu_ptr, 0);
    if (err != hipSuccess) {
        fprintf(stderr, "hipHostGetDevicePointer failed: %s\n", hipGetErrorString(err));
        hipHostUnregister(cpu_ptr);
        close(drm_fd);
        munmap(cpu_ptr, 4096);
        close(mem_fd);
        return 1;
    }
    
    printf("Step 3: HIP registered\n");
    printf("  CPU ptr: %p\n", cpu_ptr);
    printf("  GPU ptr: %p\n\n", gpu_ptr);
    
    // Launch GPU kernel to write pattern
    printf("Step 4: GPU writing pattern...\n");
    hipLaunchKernelGGL(write_pattern, dim3(1), dim3(1), 0, 0, (uint32_t*)gpu_ptr);
    hipDeviceSynchronize();
    printf("  GPU kernel completed\n\n");
    
    // Read back via CPU
    printf("Step 5: Reading pattern via CPU:\n");
    uint32_t *data = (uint32_t*)cpu_ptr;
    for (int i = 0; i < 8; i++) {
        printf("  [%2d] 0x%08x (expected: 0x%08x)\n", 
               i*4, data[i], (i+1)*0x11111111);
    }
    printf("\n");
    
    // Cleanup
    hipHostUnregister(cpu_ptr);
    close(drm_fd);
    munmap(cpu_ptr, 4096);
    close(mem_fd);
    
    printf("Now run: sudo dd if=/dev/mem bs=1 skip=$((0x80000000)) count=32 2>/dev/null | xxd\n");
    printf("to see what QEMU sees at GPA 0x80000000\n");
    
    return 0;
}
