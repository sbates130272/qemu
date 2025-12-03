#include <hip/hip_runtime.h>
#include <stdio.h>
__global__ void test() { printf("[GPU] Hello!\n"); }
int main() { 
    hipLaunchKernelGGL(test, dim3(1), dim3(1), 0, 0);
    hipDeviceSynchronize();
    return 0;
}
