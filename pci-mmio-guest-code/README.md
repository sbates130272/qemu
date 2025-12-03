# PCI MMIO Bridge - Guest Testing Infrastructure

This directory contains guest-side software for testing and demonstrating
the PCI MMIO Bridge device in QEMU. It enables GPU-initiated NVMe I/O with
support for both emulated and passthrough NVMe controllers.

## Directory Structure

```
pci-mmio-guest-code/
├── kernel/               # Linux kernel modules
│   ├── nvme_prp1_inject.c      # Auto-inject PRP1 for NVMe admin commands
│   ├── nvme_vram_dmabuf.c      # GPU VRAM P2P physical address translation
│   └── Makefile                # Build kernel modules
├── user/                 # Userspace test programs
│   ├── test-gpu-nvme-write.cpp # GPU-accelerated NVMe write test
│   └── Makefile                # Build test programs
├── run-qemu-pci-mmio-bridge    # QEMU launch script
└── .gitignore
```

## Components

### Kernel Modules

#### 1. `nvme_prp1_inject.c`

Automatically injects PRP1 (Physical Region Page) addresses for NVMe admin
commands, specifically CREATE_SQ and CREATE_CQ. This eliminates the need
for userspace to manually calculate and provide physical addresses for
admin queue structures.

**Features:**
- Intercepts NVMe admin commands via kprobe on `nvme_submit_sync_cmd`
- Detects CREATE_SQ (opcode 0x01) and CREATE_CQ (opcode 0x05)
- Resolves virtual addresses to physical addresses using `virt_to_phys`
- Injects physical addresses into PRP1 field of NVMe command

**Usage:**
```bash
cd kernel
make
sudo insmod nvme_prp1_inject.ko
# Check dmesg for PRP1 injection confirmations
```

#### 2. `nvme_vram_dmabuf.c`

Provides GPU VRAM physical address translation for peer-to-peer (P2P) DMA
between GPU VRAM and NVMe devices. Exports an ioctl interface that converts
GPU memory allocations (via dmabuf) into physical addresses suitable for
NVMe DMA operations.

**Features:**
- Accepts dmabuf file descriptors from ROCm/HIP allocations
- Supports two modes:
  - **Passthrough NVMe**: Returns P2PDMA IOVAs for real NVMe devices
  - **Emulated NVMe**: Returns GPU BAR GPAs for QEMU emulated controllers
- Uses TTM (Translation Table Manager) resource introspection to extract
  precise VRAM offsets within the GPU BAR
- Validates memory is in VRAM (not GTT/system RAM)
- Supports dynamic dmabuf attachment with P2P enabled

**IOCTL Interface:**
```c
struct nvme_vram_dmabuf_req {
    int dmabuf_fd;           // Input: dmabuf FD from ROCm
    __u16 nvme_bdf;          // Input: NVMe BDF (0xBBDD format)
    __u32 flags;             // Reserved
    __u64 phys_addr;         // Output: Physical/GPA address
    __u64 size;              // Output: Buffer size
};

ioctl(fd, NVME_VRAM_GET_PHYS_ADDR, &req);
```

**Usage:**
```bash
cd kernel
make
sudo insmod nvme_vram_dmabuf.ko
# Device node: /dev/nvme_vram_dmabuf
```

**Internal Implementation:**
- Retrieves `dma_buf` from file descriptor
- Finds GPU PCI device (AMD vendor ID)
- Locates GPU BAR0 (VRAM aperture)
- Uses `dma_buf_dynamic_attach()` with P2P support enabled
- Extracts VRAM offset from `ttm_buffer_object->resource->start`
- Calculates final address: `BAR_base + VRAM_offset`

### Test Program

#### `test-gpu-nvme-write.cpp`

A comprehensive GPU-accelerated test program that demonstrates end-to-end
GPU-initiated NVMe I/O. Written in HIP (C++ for AMD GPUs), it showcases:

**Key Features:**
1. **GPU Data Generation**: HIP kernel generates LFSR (Linear Feedback
   Shift Register) test patterns directly in GPU VRAM
2. **GPU Command Submission**: GPU threads formulate and submit NVMe write
   commands without CPU intervention
3. **Dual Doorbell Modes**:
   - **Bridge Mode**: GPU → PCI MMIO Bridge → NVMe (for emulated)
   - **Direct Mode**: GPU → NVMe BAR (for passthrough, `--direct-doorbell`)
4. **VRAM P2P Support**: Automatic physical address resolution via dmabuf
   kernel module
5. **Data Verification**: Reads back from NVMe to verify correct pattern

**Command-Line Options:**
```
Usage: test-gpu-nvme-write [options] <nvme_device> <start_lba> <num_blocks>

Options:
  -d, --device-memory      Use GPU VRAM instead of host memory
  --seed=0xXXXXXXXX       LFSR seed (default: 0x00000001)
  --direct-doorbell        Ring NVMe doorbell directly (passthrough only)
  -h, --help              Show help

Examples:
  # Emulated NVMe via bridge (host memory)
  sudo ./test-gpu-nvme-write /dev/nvme0n1 0 1
  
  # Emulated NVMe via bridge (VRAM P2P)
  sudo ./test-gpu-nvme-write -d --seed=0x12345678 /dev/nvme0n1 0 8
  
  # Passthrough NVMe with direct doorbell (VRAM P2P)
  sudo ./test-gpu-nvme-write -d --direct-doorbell /dev/nvme1n1 100 8
```

**Test Flow:**
1. Detect NVMe controller BDF from sysfs
2. Allocate data buffer (host or VRAM based on `-d` flag)
3. Generate LFSR pattern on GPU
4. Get physical address:
   - Host memory: via `/proc/self/pagemap`
   - VRAM: via `nvme_vram_dmabuf` kernel module ioctl
5. Setup NVMe I/O queues (SQ/CQ)
6. Launch GPU kernel to submit NVMe write command
7. Poll for completion
8. Verify data on disk

**GPU Kernel Functions:**
- `fill_buffer_lfsr_kernel()`: Generates LFSR pattern in buffer
- `gpu_submit_nvme_write()`: Formulates NVMe command and rings doorbell

**Prerequisites:**
- ROCm 5.0+ with HIP support
- AMD GPU with PCIe P2P support (e.g., Radeon RX 7900 XTX)
- NVMe device (emulated or passthrough)
- Root access (for physical address access and NVMe operations)
- Kernel modules loaded (`nvme_prp1_inject`, `nvme_vram_dmabuf`)

**Build:**
```bash
cd user
make
# Produces: test-gpu-nvme-write
```

**Compilation Details:**
- Compiler: `/opt/rocm/bin/hipcc`
- Libraries: `-lhsa-runtime64 -ldrm -ldrm_amdgpu`
- Includes: DRM/AMDGPU headers for GPU memory management

### QEMU Launch Script

#### `run-qemu-pci-mmio-bridge`

Preconfigured QEMU command line for launching a guest VM with:
- PCI MMIO Bridge device (`-device pci-mmio-bridge`)
- VFIO GPU passthrough (AMD Radeon RX 7900 XTX at 0000:c3:00.0)
- Optional VFIO NVMe passthrough (commented out, 0000:c1:00.0)
- Emulated NVMe with VRAM P2P trace events enabled
- Ubuntu 24.10 guest image
- Virtio-9p shared filesystem for `/home/stebates/Projects`
- 32 CPU cores, 64GB RAM, KVM acceleration

**VRAM P2P Trace Events Enabled:**
```bash
-trace pci_nvme_vram_p2p_read
-trace pci_nvme_vram_p2p_mr_found
-trace pci_nvme_vram_p2p_direct_ptr
```

**Usage:**
```bash
./run-qemu-pci-mmio-bridge
# Guest VM boots with GPU and bridge ready
# SSH to guest, then run tests
```

## Prerequisites

### Host System
- Linux kernel 5.15+ (for VFIO and P2PDMA support)
- QEMU 10.1.0+ (with PCI MMIO Bridge and VRAM P2P patches)
- VFIO-enabled IOMMU groups for GPU passthrough
- AMD ROCm 5.0+ installed

### Guest System
- Linux kernel 6.8+ (for DMA-BUF and TTM APIs)
- Kernel headers installed (`linux-headers-$(uname -r)`)
- Build tools: `make`, `gcc`
- ROCm installed in guest (for HIP runtime)
- DRM/libdrm development headers

## Complete Workflow

### 1. Build and Launch QEMU
```bash
# On host
cd /home/stebates/Projects/qemu
./pci-mmio-guest-code/run-qemu-pci-mmio-bridge
```

### 2. Build Kernel Modules in Guest
```bash
# In guest VM
cd ~/Projects/qemu/pci-mmio-guest-code/kernel
make

# Load modules
sudo insmod nvme_prp1_inject.ko
sudo insmod nvme_vram_dmabuf.ko

# Verify
lsmod | grep nvme
ls -l /dev/nvme_vram_dmabuf
```

### 3. Build Test Program
```bash
cd ../user
make
```

### 4. Run Tests

**Test 1: Host Memory (Baseline)**
```bash
sudo ./test-gpu-nvme-write /dev/nvme0n1 0 1
```

**Test 2: VRAM P2P (Emulated NVMe via Bridge)**
```bash
sudo ./test-gpu-nvme-write -d --seed=0x00000040 /dev/nvme0n1 0 1
```

**Test 3: VRAM P2P (Passthrough NVMe, Direct Doorbell)**
```bash
# If /dev/nvme1n1 is passthrough device
sudo ./test-gpu-nvme-write -d --direct-doorbell --seed=0x00000040 \
     /dev/nvme1n1 0 1
```

### 5. Verify Results
```bash
# Read back data from NVMe
sudo nvme read /dev/nvme0n1 -s 0 -c 0 -z 512 | hexdump -C

# Should show LFSR pattern starting with seed value
# e.g., for seed 0x00000040:
#   00000000: 40 00 00 00 20 00 00 00 10 00 00 00 88 00 00 00
```

## How It Works

### Emulated NVMe (via Bridge)
```
GPU VRAM Buffer → GPU generates LFSR pattern
     ↓
GPU formulates NVMe write command (PRP1 = VRAM GPA)
     ↓
GPU writes doorbell value to PCI MMIO Bridge shadow buffer
     ↓
PCI MMIO Bridge intercepts, forwards to emulated NVMe controller
     ↓
QEMU NVMe emulation detects VRAM address range
     ↓
nvme_map_addr_vram() maps GPU BAR directly (no copy!)
     ↓
Data written to virtual NVMe disk
```

### Passthrough NVMe (Direct Doorbell)
```
GPU VRAM Buffer → GPU generates LFSR pattern
     ↓
GPU formulates NVMe write command (PRP1 = P2PDMA IOVA)
     ↓
GPU writes doorbell value directly to NVMe BAR
     ↓
Real NVMe controller performs P2P DMA from GPU VRAM
     ↓
Data written to physical NVMe SSD
```

## Troubleshooting

### Kernel Module Build Fails
```bash
# Ensure kernel headers are installed
sudo apt install linux-headers-$(uname -r)
```

### Test Program Build Fails
```bash
# Ensure ROCm and development libraries are installed
sudo apt install rocm-dev libdrm-dev libdrm-amdgpu1
```

### VRAM Physical Address Fails
```bash
# Check kernel module is loaded
lsmod | grep nvme_vram_dmabuf
# Check device node exists
ls -l /dev/nvme_vram_dmabuf
# Check dmesg for errors
dmesg | grep nvme_vram
```

### Bridge Not Found
```bash
# In guest, check PCI devices
lspci | grep -i bridge
# Should show: 00:04.0 System peripheral: Red Hat, Inc. Device 10f0
```

### GPU Not Accessible
```bash
# Check GPU is visible in guest
lspci | grep -i vga
rocm-smi
# Ensure VFIO passthrough is configured correctly
```

## Performance Notes

- **VRAM P2P** eliminates host memory staging, providing near-native
  throughput for large transfers
- **Direct doorbell mode** reduces latency by ~1-2μs compared to bridge mode
- **Bridge mode** is required for emulated NVMe but adds minimal overhead
  (<100ns per doorbell write)

## References

- [QEMU PCI MMIO Bridge Documentation](../docs/system/devices/pci-mmio-bridge.rst)
- [NVMe Specification](https://nvmexpress.org/specifications/)
- [ROCm Documentation](https://rocm.docs.amd.com/)
- [Linux DMA-BUF](https://www.kernel.org/doc/html/latest/driver-api/dma-buf.html)

## License

This software is provided under the same license as QEMU (GPL-2.0-or-later).

## Author

Stephen Bates <sbates@raithlin.com>

