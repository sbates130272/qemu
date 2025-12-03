/*
 * Check where GPU writes actually go
 * 
 * Compile: hipcc -lhsa-runtime64 -o check-gpu-writes check-gpu-writes.cpp
 * Run: sudo ./check-gpu-writes
 */

#include <hip/hip_runtime.h>
#include <hsa/hsa.h>
#include <hsa/hsa_ext_amd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

__global__ void gpu_write_test(uint32_t *ptr, uint32_t value)
{
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        *ptr = value;
        __threadfence_system();
        printf("[GPU] Wrote value 0x%08x to address %p\n", value, ptr);
    }
}

int main()
{
    void *shadow_cpu;
    void *gpu_buffer;
    int fd;
    uint64_t shadow_gpa = 0x80000000;
    uint32_t shadow_size = 4096;
    hsa_status_t hsa_status;
    hipError_t err;
    
    printf("=================================================\n");
    printf("GPU Write Location Test\n");
    printf("=================================================\n\n");
    
    /* Map shadow buffer */
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    shadow_cpu = mmap(NULL, shadow_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, fd, shadow_gpa);
    close(fd);
    
    printf("CPU mapping: %p (GPA 0x%llx)\n", shadow_cpu, 
           (unsigned long long)shadow_gpa);
    
    /* Initialize HSA and lock memory */
    hsa_init();
    
    hsa_agent_t gpu_agent = {0};
    auto find_gpu = [](hsa_agent_t agent, void* data) -> hsa_status_t {
        hsa_device_type_t device_type;
        hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);
        if (device_type == HSA_DEVICE_TYPE_GPU) {
            *((hsa_agent_t*)data) = agent;
            return HSA_STATUS_INFO_BREAK;
        }
        return HSA_STATUS_SUCCESS;
    };
    hsa_iterate_agents(find_gpu, &gpu_agent);
    
    hsa_status = hsa_amd_memory_lock(shadow_cpu, shadow_size, 
                                     &gpu_agent, 1, &gpu_buffer);
    
    printf("GPU mapping: %p\n\n", gpu_buffer);
    
    /* Clear memory via CPU */
    printf("Step 1: CPU clears memory...\n");
    *(uint32_t*)shadow_cpu = 0;
    printf("  Value at CPU ptr: 0x%08x\n", *(uint32_t*)shadow_cpu);
    printf("  Value at GPA (via /dev/mem): ");
    
    int fd2 = open("/dev/mem", O_RDONLY | O_SYNC);
    void *check_ptr = mmap(NULL, 4, PROT_READ, MAP_SHARED, fd2, shadow_gpa);
    printf("0x%08x\n\n", *(uint32_t*)check_ptr);
    munmap(check_ptr, 4);
    close(fd2);
    
    /* GPU writes */
    printf("Step 2: GPU writes 0xDEADBEEF...\n");
    hipLaunchKernelGGL(gpu_write_test, dim3(1), dim3(1), 0, 0,
                       (uint32_t*)gpu_buffer, 0xDEADBEEF);
    hipDeviceSynchronize();
    printf("\n");
    
    /* Check where it went */
    printf("Step 3: Checking where GPU wrote...\n");
    printf("  Value at CPU ptr (0x%p): 0x%08x\n", 
           shadow_cpu, *(uint32_t*)shadow_cpu);
    
    fd2 = open("/dev/mem", O_RDONLY | O_SYNC);
    check_ptr = mmap(NULL, 4, PROT_READ, MAP_SHARED, fd2, shadow_gpa);
    printf("  Value at GPA 0x%llx (via /dev/mem): 0x%08x\n",
           (unsigned long long)shadow_gpa, *(uint32_t*)check_ptr);
    munmap(check_ptr, 4);
    close(fd2);
    
    printf("\n");
    
    if (*(uint32_t*)shadow_cpu == 0xDEADBEEF) {
        printf("✅ GPU write visible via CPU pointer!\n");
    } else {
        printf("❌ GPU write NOT visible via CPU pointer\n");
    }
    
    fd2 = open("/dev/mem", O_RDONLY | O_SYNC);
    check_ptr = mmap(NULL, 4, PROT_READ, MAP_SHARED, fd2, shadow_gpa);
    if (*(uint32_t*)check_ptr == 0xDEADBEEF) {
        printf("✅ GPU write visible at GPA 0x80000000!\n");
        printf("   → hsa_amd_memory_lock preserved GPA mapping!\n");
    } else {
        printf("❌ GPU write NOT visible at GPA 0x80000000\n");
        printf("   → GPU writes went to a different physical address\n");
    }
    munmap(check_ptr, 4);
    close(fd2);
    
    printf("\n=================================================\n");
    
    hsa_amd_memory_unlock(shadow_cpu);
    hsa_shut_down();
    munmap(shadow_cpu, shadow_size);
    
    return 0;
}

