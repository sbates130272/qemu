# PCI MMIO Bridge - Guest Visibility

## ✅ PCI Device Version: Hybrid Architecture

The PCI MMIO Bridge uses a **hybrid architecture** for both discoverability
AND VFIO DMA compatibility:

### Architecture
1. **PCI Device**: Discoverable via `lspci` (Vendor 0x1b36, Device 0x0010)
2. **Shadow Buffer**: Allocated in **guest RAM** (NOT PCI MMIO space)
3. **Config Space**: Exposes shadow buffer GPA via vendor-specific registers

### Why This Design?

**Critical**: VFIO's Type-1 IOMMU can only map **guest RAM**, not PCI MMIO
space. A traditional PCI BAR would NOT work for VFIO DMA.

### How Guests Access It

```c
/* 1. Discover PCI device */
lspci  // Shows: "System peripheral: Red Hat, Inc. Device 0015"

/* 2. Read shadow buffer GPA from PCI config space (offset 0x40) */
uint32_t gpa_lo = pci_config_read(pdev, 0x40);
uint32_t gpa_hi = pci_config_read(pdev, 0x44);
uint64_t shadow_gpa = ((uint64_t)gpa_hi << 32) | gpa_lo;

/* 3. Map shadow buffer (it's guest RAM, not MMIO) */
void __iomem *shadow = ioremap(shadow_gpa, 4096);

/* 4. VFIO devices can DMA to shadow_gpa (IOVA = GPA) */
vfio_iommu_map_dma(container, shadow_gpa, size, ...);
```

See `docs/system/devices/pci-mmio-bridge-pci.rst` for complete documentation.

---

## Machine-Integrated Version: Fixed GPA

**The bridge is currently NOT visible to the guest OS in any standard way.**

### What You WON'T See

When you boot a VM with the bridge enabled, the guest will NOT see:
- ❌ A new PCI device
- ❌ An ACPI device
- ❌ An entry in `/proc/iomem`
- ❌ Anything in `dmesg`
- ❌ Any fw_cfg entries

### What Actually Happens

The bridge is just a **memory region** at a fixed guest physical address:
- **Address**: `0x80000000` (default, configurable)
- **Size**: `4096` bytes (default)
- **Type**: Regular guest RAM (from the guest's perspective)

### How Guest Software Finds It

Currently, guest software needs to:

1. **Know the GPA in advance** (hardcoded or passed via kernel parameter)
2. **Map it** using standard memory mapping:

```c
// In Linux kernel driver
void __iomem *bridge = ioremap(0x80000000, 4096);

// Check if it's initialized
struct pci_mmio_ring_meta *meta = (void *)bridge;
if (meta->queue_depth > 0) {
    printk("PCI MMIO Bridge found at 0x80000000\n");
    printk("Queue depth: %u commands\n", meta->queue_depth);
}
```

3. **Or from userspace** (if exposed):

```c
// Open /dev/mem
int fd = open("/dev/mem", O_RDWR | O_SYNC);
void *bridge = mmap(NULL, 4096, PROT_READ|PROT_WRITE, 
                    MAP_SHARED, fd, 0x80000000);
```

## Testing Guest Visibility

### From Within Guest (Linux)

Boot your VM and run these commands:

```bash
# Check if memory region exists (won't show the bridge specifically)
cat /proc/iomem | grep -i 80000000
# (You won't see it listed as "pci-mmio-bridge")

# Try to access it (requires root and CONFIG_DEVMEM)
sudo dd if=/dev/mem bs=1 count=24 skip=$((0x80000000)) 2>/dev/null | hexdump -C
# If bridge is initialized, you should see non-zero data:
#   00000000  00 00 00 00 00 00 00 00  a9 00 00 00 ...
#             ^producer  ^consumer     ^queue_depth (169 = 0xa9)
```

### Test Script for Guest

Save this inside your guest VM:

```bash
#!/bin/bash
# test-pci-mmio-bridge.sh

BRIDGE_GPA=0x80000000

echo "=== PCI MMIO Bridge Discovery Test ==="
echo ""

# Check if we can access /dev/mem
if [ ! -r /dev/mem ]; then
    echo "ERROR: Cannot read /dev/mem (need root or CONFIG_DEVMEM)"
    exit 1
fi

echo "Checking for PCI MMIO Bridge at GPA $BRIDGE_GPA..."

# Read first 24 bytes (ring metadata)
hexdump=$(sudo dd if=/dev/mem bs=1 count=24 skip=$((BRIDGE_GPA)) 2>/dev/null | hexdump -C)

echo "Raw memory at $BRIDGE_GPA:"
echo "$hexdump"
echo ""

# Extract queue_depth (bytes 8-11, little-endian)
queue_depth=$(sudo dd if=/dev/mem bs=1 count=4 skip=$((BRIDGE_GPA + 8)) 2>/dev/null | \
              hexdump -e '"%u"')

if [ "$queue_depth" -gt 0 ] && [ "$queue_depth" -lt 1000 ]; then
    echo "✅ PCI MMIO Bridge FOUND!"
    echo "   Queue depth: $queue_depth commands"
    echo "   Location: $BRIDGE_GPA"
else
    echo "❌ PCI MMIO Bridge NOT initialized"
    echo "   (All zeros or invalid data)"
fi
```

## Adding Discovery (Future Enhancement)

To make the bridge properly discoverable, we should add one of:

### Option 1: fw_cfg Entry (Easiest)

Add to QEMU code:
```c
fw_cfg_add_i64(fw_cfg, FW_CFG_FILE_FIRST, bridge_gpa);
fw_cfg_add_i32(fw_cfg, FW_CFG_FILE_FIRST+1, bridge_size);
```

Guest can discover via:
```bash
# In Linux guest
cat /sys/firmware/qemu_fw_cfg/by_name/opt/pci_mmio_bridge_gpa/raw
```

### Option 2: ACPI Table (Standard Approach)

Add an ACPI device:
```
Device (PMMB) {
    Name (_HID, "QEMU0001")  // Hardware ID
    Name (_STR, Unicode("PCI MMIO Bridge"))
    Name (_CRS, ResourceTemplate() {
        Memory32Fixed(ReadWrite, 0x80000000, 0x1000)
    })
}
```

Guest will see it in:
- `ls /sys/bus/acpi/devices/`
- `dmesg | grep QEMU0001`

### Option 3: Virtual PCI Device

Create an actual PCI device that exposes bridge info in config space.
Most visible but most complex.

## Workaround for Now

Until we add discovery, document the address in:

1. **Kernel Parameter**:
   ```
   qemu-mmio-bridge.gpa=0x80000000
   ```

2. **Device Tree** (for ARM):
   ```
   pci-mmio-bridge@80000000 {
       compatible = "qemu,pci-mmio-bridge";
       reg = <0x80000000 0x1000>;
   };
   ```

3. **Hardcoded in Driver**:
   ```c
   #define PCI_MMIO_BRIDGE_GPA 0x80000000ULL
   ```

## Example: Working Guest Driver

Despite no discovery mechanism, a guest driver can still use it:

```c
// pci_mmio_bridge_guest.c
#include <linux/module.h>
#include <linux/io.h>

#define BRIDGE_GPA 0x80000000ULL
#define BRIDGE_SIZE 4096

static void __iomem *bridge_mem;

static int __init pci_mmio_bridge_init(void)
{
    struct pci_mmio_ring_meta *meta;
    
    // Map the bridge
    bridge_mem = ioremap(BRIDGE_GPA, BRIDGE_SIZE);
    if (!bridge_mem) {
        pr_err("Failed to map PCI MMIO bridge\n");
        return -ENOMEM;
    }
    
    // Check if initialized
    meta = (struct pci_mmio_ring_meta *)bridge_mem;
    if (meta->queue_depth == 0) {
        pr_warn("PCI MMIO bridge not initialized by QEMU\n");
        iounmap(bridge_mem);
        return -ENODEV;
    }
    
    pr_info("PCI MMIO Bridge found at 0x%llx\n", BRIDGE_GPA);
    pr_info("Queue depth: %u commands\n", meta->queue_depth);
    
    return 0;
}

static void __exit pci_mmio_bridge_exit(void)
{
    if (bridge_mem)
        iounmap(bridge_mem);
}

module_init(pci_mmio_bridge_init);
module_exit(pci_mmio_bridge_exit);
MODULE_LICENSE("GPL");
```

## Summary

**Current State**:
- ❌ No automatic discovery
- ✅ Can be accessed at known GPA (0x80000000)
- ✅ Works fine if guest knows the address
- 📋 Should add fw_cfg/ACPI in future

**What Guest Sees Right Now**:
- Nothing obvious
- Just memory at 0x80000000 that happens to contain command queue

**How to Use It**:
- Guest driver needs hardcoded GPA
- Or pass GPA via kernel parameter
- Or add discovery mechanism (fw_cfg recommended)

---

**Want me to add fw_cfg discovery?** It's a simple enhancement that would make
the bridge properly discoverable by guest software.

