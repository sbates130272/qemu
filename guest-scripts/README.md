# Guest VM Scripts for PCI MMIO Bridge

# Working Nov 28th

```
sudo HSA_FORCE_FINE_GRAIN_PCIE=1 ./test-gpu-bridge-testdev
```
```
rocm-axiio login: pci_mmio_bridge_write BDF=0028 BAR=2 offset=0x0 value=0xdeadbeefcafebabe size=8
pci_mmio_bridge_poll_processed processed 1 commands
pci_mmio_bridge_read BDF=0028 BAR=2 offset=0x0 value=0xdeadbeefcafebabe size=8
pci_mmio_bridge_poll_processed processed 1 commands
pci_mmio_bridge_write BDF=0028 BAR=2 offset=0x0 value=0xdeadbeefcafebabe size=8
pci_mmio_bridge_poll_processed processed 1 commands
pci_mmio_bridge_read BDF=0028 BAR=2 offset=0x0 value=0xdeadbeefcafebabe size=8
pci_mmio_bridge_poll_processed processed 1 commands
```
Scripts to run **inside the guest VM** to detect and test the PCI MMIO Bridge.

## detect-pci-mmio-bridge.sh

Detects if the PCI MMIO Bridge is present and initialized.

### Usage

1. Copy this script to your guest VM:
   ```bash
   scp detect-pci-mmio-bridge.sh guest-vm:/tmp/
   ```

2. Inside the guest VM, run:
   ```bash
   sudo bash /tmp/detect-pci-mmio-bridge.sh
   ```

### Requirements

- Root access (sudo)
- Kernel with `CONFIG_DEVMEM=y` (most distributions)
- One of: `xxd`, `hexdump`, or `od` (standard on most Linux systems)

### Example Output

**When bridge is present**:
```
==========================================================
PCI MMIO BRIDGE DETECTED!
==========================================================

Bridge Information:
  Location (GPA):  0x80000000
  Size:            4096 bytes
  Queue Depth:     169 commands
  Command Size:    24 bytes each

The bridge is initialized and ready for use.
```

**When bridge is not present**:
```
==========================================================
❌ PCI MMIO BRIDGE NOT DETECTED
==========================================================

Possible reasons:
  1. QEMU not started with: -M pc,pci-mmio-bridge-enabled=true
  2. Bridge at different GPA (check QEMU config)
  3. Memory access restricted by kernel
```

## Alternative: Manual Check

If you can't run the script, manually check with:

```bash
# Read first 24 bytes at 0x80000000
sudo dd if=/dev/mem bs=1 count=24 skip=$((0x80000000)) 2>/dev/null | hexdump -C
```

Look for:
- Bytes 8-11: Queue depth (should be 0xa9 0x00 0x00 0x00 = 169 in little-endian)
- If all zeros: Bridge not initialized
- If non-zero queue_depth: Bridge is present!

## Accessing the Bridge from Guest Code

### C Example

```c
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>

struct pci_mmio_ring_meta {
    uint32_t producer_idx;
    uint32_t consumer_idx;
    uint32_t queue_depth;
    uint32_t reserved[3];
};

int main() {
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    
    void *ptr = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                     MAP_SHARED, fd, 0x80000000);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    
    struct pci_mmio_ring_meta *meta = ptr;
    
    printf("PCI MMIO Bridge:\n");
    printf("  Queue depth: %u\n", meta->queue_depth);
    printf("  Producer:    %u\n", meta->producer_idx);
    printf("  Consumer:    %u\n", meta->consumer_idx);
    
    munmap(ptr, 4096);
    close(fd);
    return 0;
}
```

Compile and run:
```bash
gcc -o check-bridge check-bridge.c
sudo ./check-bridge
```

### Linux Kernel Module

```c
#include <linux/module.h>
#include <linux/io.h>

static int __init bridge_detect_init(void)
{
    void __iomem *bridge;
    uint32_t queue_depth;
    
    bridge = ioremap(0x80000000, 4096);
    if (!bridge)
        return -ENOMEM;
    
    queue_depth = ioread32(bridge + 8);  // Offset 8 = queue_depth
    
    if (queue_depth > 0 && queue_depth < 1000) {
        pr_info("PCI MMIO Bridge detected: %u commands\n", 
                queue_depth);
    } else {
        pr_info("PCI MMIO Bridge not present\n");
    }
    
    iounmap(bridge);
    return 0;
}

module_init(bridge_detect_init);
MODULE_LICENSE("GPL");
```

## Troubleshooting

### "Cannot read /dev/mem"

1. **Check if CONFIG_DEVMEM is enabled**:
   ```bash
   grep CONFIG_DEVMEM /boot/config-$(uname -r)
   ```
   Should show: `CONFIG_DEVMEM=y`

2. **Check kernel parameters**:
   Some distributions disable /dev/mem access:
   ```bash
   cat /proc/cmdline | grep iomem
   ```
   If you see `iomem=relaxed`, memory access is restricted.

3. **Use root**:
   ```bash
   sudo bash detect-pci-mmio-bridge.sh
   ```

### "All zeros detected"

This means QEMU didn't initialize the bridge. Check:

1. **QEMU command line**:
   ```bash
   ps aux | grep qemu
   ```
   Should contain: `-M pc,pci-mmio-bridge-enabled=true`

2. **Different GPA**:
   If QEMU uses a different address, modify the script:
   ```bash
   BRIDGE_GPA=0x90000000  # Change to match QEMU config
   ```

## See Also

- `../docs/pci-mmio-bridge-quickstart.txt` - Quick start guide
- `../docs/system/devices/pci-mmio-bridge.rst` - Full documentation
- `../GUEST_VISIBILITY.md` - Detailed visibility information

