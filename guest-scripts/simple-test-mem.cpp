#include <hip/hip_runtime.h>
#include <stdio.h>

__global__ void write_magic(int *ptr) { 
    *ptr = 0xDEADBEEF; 
}

int main() {
    int *d_ptr, h_value = 0;
    
    hipMalloc(&d_ptr, sizeof(int));
    hipMemcpy(d_ptr, &h_value, sizeof(int), hipMemcpyHostToDevice);
    
    printf("[CPU] Before kernel: value = 0x%X\n", h_value);
    
    hipLaunchKernelGGL(write_magic, dim3(1), dim3(1), 0, 0, d_ptr);
    hipDeviceSynchronize();
    
    hipMemcpy(&h_value, d_ptr, sizeof(int), hipMemcpyDeviceToHost);
    printf("[CPU] After kernel: value = 0x%X\n", h_value);
    
    if (h_value == 0xDEADBEEF) {
        printf("✓ GPU KERNEL EXECUTED!\n");
    } else {
        printf("✗ GPU kernel did NOT execute (value = 0x%X)\n", h_value);
    }
    
    hipFree(d_ptr);
    return 0;
}
