#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <stddef.h>
#include <stdint.h>

#include "hw.h"
#include "vmcs.h"
#include "vmx_ops.h"
#include "vmx_consts.h"


int setup_vmxon_region(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    vcpu->vmxon = (struct vmxon_region *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
    if(!vcpu->vmxon)
        return -ENOMEM;

    *(uint32_t *)vcpu->vmxon = _vmcs_revision_id();
    vcpu->vmxon_pa = virt_to_phys(vcpu->vmxon);

    return 0;
}

int setup_vmcs_region(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    uint32_t vmcs_size = _get_vmcs_size();
    size_t alloc_size = (vmcs_size <= PAGE_SIZE) ? PAGE_SIZE : PAGE_ALIGN(vmcs_size);

    vcpu->vmcs = (struct vmcs *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(alloc_size));
    if(!vcpu->vmcs)
        return -ENOMEM;

    *(uint32_t *)vcpu->vmcs = _vmcs_revision_id();
    vcpu->vmcs_pa = virt_to_phys(vcpu->vmcs);

    return 0;
}

int setup_io_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    vcpu->io_bitmap = (uint32_t *)__get_free_page(GFP_KERNEL);
    if(!vcpu->io_bitmap)
        return -ENOMEM;

    memset(vcpu->io_bitmap, 0, VMCS_IO_BITMAP_SIZE);
    vcpu->io_bitmap_pa = virt_to_phys(vcpu->io_bitmap);

    if(_vmwrite(VMCS_IO_BITMAP_A, (uint64_t)vcpu->io_bitmap_pa) != 0) {
        free_io_bitmap(vcpu);
        return -EIO;
    }

    if(_vmwrite(VMCS_IO_BITMAP_B, (uint64_t)vcpu->io_bitmap + VMCS_IO_BITMAP_PAGES_ORDER) != 0) {
        free_io_bitmap(vcpu);
        return -EIO;
    }

    return 0;
}

int setup_msr_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    vcpu->msr_bitmap = kmalloc(PAGE_SIZE | __GFP_ZERO, GFP_KERNEL);
    if(!vcpu->msr_bitmap)
        return -ENOMEM;

    vcpu->msr_bitmap_pa = virt_to_phys(vcpu->msr_bitmap); 
}

int setup_vmxon_region(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    /*allocate one page, page-aligned, zeroed */ 
    vcpu->vmxon = (struct vmxon_region *)__get_free_page(GFP_KERNEL | __GFP_ZERO); 
    if(!vcpu->vmxon)
        return -ENOMEM; 

    /*set VMX revision identifier */ 
    *(uint32_t *)vcpu->vmxon = _vmcs_revision_id(); 
    vcpu->vmxon_pa = virt_to_phys(vcpu->vmxon); 

    return 0; 

}

int setup_vmcs_region(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL; 

    uint32_t vmcs_size = _get_vmcs_size(); 
    size_t alloc_size = (vmcs_size <= PAGE_SIZE) ? PAGE_SIZE : PAGE_ALIGN(vmcs_size); 

    vcpu->vmcs = (struct vmcs *)__get_free_pages(
        GFP_KERNEL | __GFP_ZERO, get_order(alloc_size)); 
    if(!vcpu->vmcs)
        return -ENOMEM; 

    *(uint32_t *)vcpu->vmcs = _vmcs_revision_id();
    vcpu->vmcs_pa = virt_to_phys(vcpu->vmcs); 

    return 0;

}

/*which IO operation */ 
int setup_io_bitmap(struct vcpu *vcpu)
{
    if(!vcpu)
        return -EINVAL;

    vcpu->io_bitmap = (uint32_t *)__get_free_page(
        GFP_KERNEL); 
    if(!vcpu->io_bitmap)
    {
        pr_err("Failed to allocate I/O bitmap memory\n"); 
        return -ENOMEM; 
    }

    /* clear entire I/O bitmap (all 0  == allow all ports) */ 
    memset(vcpu->io_bitmap, 0, VMCS_IO_BITMAP_SIZE);

    vcpu->io_bitmap_pa = virt_to_phys(vcpu->io_bitmap); 
    
    pr_info("Allocated and cleared I/O bitmap at VA %p PA 0x%llx\n", 
            vcpu->io_bitmap, (unsigned long long )vcpu->io_bitmap_pa);

    /*write the address to the VMCS */ 
    if(_vmwrite(VMCS_IO_BITMAP_A, (uint64_t)vcpu->io_bitmap_pa) != 0)
    {
        pr_err("VMWrite VMCS_IO_BITMAP_A failed\n");
        free_io_bitmap(vcpu); 
        return -EIO; 
    }

    if(_vmwrite(VMCS_IO_BITMAP_B, (uint64_t)vcpu->io_bitmap + VMCS_IO_BITMAP_PAGES_ORDER) != 0)
    {
        pr_err("VMWrite VMCS_IO_BITMAP_B failed\n"); 
        free_io_bitmap(vcpu); 
        return -EIO; 
    }

    pr_info("VMCS I/O Bitmap field set successfully\n"); 
    return 0; 

}

/*MSRs that case VM exit when accessed by guest */ 
int setup_msr_bitmap(struct vcpu *vcpu)
{
    vcpu->msr_bitmap = kmalloc(PAGE_SIZE | __GFP_ZERO); 
    if(!vcpu->msr_bitmap)
    {
        pr_info("Failed to allocate MSR bitmap\n"); 
        return -ENOMEM;
    }

    vcpu->msr_bitmap_pa = virt_to_phys(vcpu->msr_bitmap); 

    /*mark IA32_SYSENTER_CS as causing a VM exit */ 
    uint32_t msr_index = IA32_SYSENTER_CS;
    uint8_t *bitmap = (uint8_t*)vcpu->msr_bitmap;
    uint32_t byte = msr_index / 8;
    uint8_t bit = msr_index % 8; 
    bitmap[byte] |= (1 << bit); 


    if(_vmwrite(VMCS_MSR_BITMAP, vcpu->msr_bitmap_pa) != 0){
        free_msr_bitmap(vcpu); 
    }
}

/*util round size up to full pagess and computer order */ 
static inline unsigned int msr_area_order(size_t bytes)
{
    size_t pages  = DIV_ROUND_UP(bytes, PAGE_SIZE); 
    return get_order(pages * PAGE_SIZE); 
}

static struct msr_entry *alloc_msr_entry(size_t n_entries)
{
    size_t size = n_entries * sizeof(struct msr_entry); 
    unsigned int order = msr_area_order(size); 

    struct page *p = alloc_pages(GFP_KERNEL | __GFP_ZERO, order); 
    if(!p)
        return NULL; 

    return (struct msr_entry*)page_address(p); 
}

static void free_msr_area(struct msr_entry *area, size_t n_entries)
{
    if(!area)
        return; 

    size_t size = n_entries * sizeof(struct msr_entry); 
    unsigned int order = msr_area_order(size); 
    free_pages((unsigned long)area, order); 
}

/*populate msr-load are from parallel arrays */ 
static void populate_msr_load_area(struct msr_entry *area, size_t count,
                              const uint32_t *indices, const uint32_t *values)
{
    size_t i; 
    for(i = 0; i < count; ++i)
    {
        area[i].index = indices[i]; 
        area[i].reserved = 0; 
        area[i].value = values[i]; 
    }

}

/*populate MSR-store areas index fields. CPU will write this values on VM-exit */ 
static void populate_msr_store_area(struct msr_entry *area, size_t count, 
                                    const uint32_t *indices)
{
    size_t i;
    for(i = 0; i < count; ++i)
    {
        area[i].index = indices[i];
        area[i].reserved = 0; 
        area[i].value = 0; 
    }

}

int setup_msr_areas(struct vcpu *vcpu, 
                    const uint32_t *vmexit_list, size_t vmexit_count, 
                    const uint32_t *vmentry_list, const uint32_t *vmentry_values, 
                    size_t vmentry_count)
{
    struct msr_entry *vmexit_store = NULL;
    struct msr_entry *vmexit_load = NULL; 
    struct msr_entry *vmentry_load = NULL; 

}
struct vcpu *create_vcpu(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu;

    /* Allocate zeroed VCPU struct */
    vcpu = kzalloc(sizeof(*vcpu), GFP_KERNEL);
    if (!vcpu)
        return NULL;

    vcpu->vm = vm;
    vcpu->vcpu_id = vcpu_id;

    /* Initialize spinlock */
    spin_lock_init(&vcpu->lock);

    /* Allocate and setup VMXON region */
    if (setup_vmxon_region(vcpu) != 0) {
        pr_err("Failed to setup VMXON region\n");
        kfree(vcpu);
        return NULL;
    }

    /* Allocate and setup VMCS region */
    if (setup_vmcs_region(vcpu) != 0) {
        pr_err("Failed to setup VMCS region\n");
        free_pages((unsigned long)vcpu->vmxon, 0); // free VMXON
        kfree(vcpu);
        return NULL;
    }

    /* Setup IO bitmap */
    if (setup_io_bitmap(vcpu) != 0) {
        pr_err("Failed to setup I/O bitmap\n");
        free_pages((unsigned long)vcpu->vmcs, get_order(_get_vmcs_size()));
        free_pages((unsigned long)vcpu->vmxon, 0);
        kfree(vcpu);
        return NULL;
    }

    /* Setup MSR bitmap */
    if (setup_msr_bitmap(vcpu) != 0) {
        pr_err("Failed to setup MSR bitmap\n");
        free_pages((unsigned long)vcpu->io_bitmap, VMCS_IO_BITMAP_PAGES_ORDER);
        free_pages((unsigned long)vcpu->vmcs, get_order(_get_vmcs_size()));
        free_pages((unsigned long)vcpu->vmxon, 0);
        kfree(vcpu);
        return NULL;
    }

    pr_info("VCPU %d created successfully\n", vcpu_id);
    return vcpu;
}

void free_io_bitmap(struct vcpu *vcpu)
{
    if (vcpu->io_bitmap) {
        free_pages((unsigned long)vcpu->io_bitmap, VMCS_IO_BITMAP_PAGES_ORDER);
        vcpu->io_bitmap = NULL;
        vcpu->io_bitmap_pa = 0;
    }
}

void free_msr_bitmap(struct vcpu *vcpu)
{
    if (vcpu->msr_bitmap) {
        kfree(vcpu->msr_bitmap);
        vcpu->msr_bitmap = NULL;
        vcpu->msr_bitmap_pa = 0;
    }
}

void free_vmcs_region(struct vcpu *vcpu)
{
    if (vcpu->vmcs) {
        free_pages((unsigned long)vcpu->vmcs, get_order(_get_vmcs_size()));
        vcpu->vmcs = NULL;
        vcpu->vmcs_pa = 0;
    }
}

void free_vmxon_region(struct vcpu *vcpu)
{
    if (vcpu->vmxon) {
        free_pages((unsigned long)vcpu->vmxon, 0); // VMXON is 1 page
        vcpu->vmxon = NULL;
        vcpu->vmxon_pa = 0;
    }
}

/* Free the entire VCPU */
void free_vcpu(struct vcpu *vcpu)
{
    if (!vcpu)
        return;

    free_io_bitmap(vcpu);
    free_msr_bitmap(vcpu);
    free_vmcs_region(vcpu);
    free_vmxon_region(vcpu);

    kfree(vcpu);
}
