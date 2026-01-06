#include <cerrno>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <asm/io.h>
#include <asm/msr.h>

#include <stdint.h>
#include <vmx.h>
#include <ept.h>
#include <vmx_ops.h>


bool kvx_ept_check_support(void)
{
    uint64_t ept_vpid_cap; 

    ept_vpid_cap = __rdmsr1(MSR_IA32_VMX_EPT_VPID_CAP); 

    if(!(ept_vpid_cap & EPT_CAP_PAGE_WALK_4))
    {
        pr_err("KVX: EPT 4-level page walk not supported\n"); 
        return false; 
    }

    if(!(ept_vpid_cap & EPT_CAP_MEMTYPE_WB))
    {
        pr_err("KVX: EPT write-back memory type not supported\n"); 
        return false; 
    }

    if(!(ept_vpid_cap & EPT_CAP_INVEPT))
    {
        pr_err("KVX: INVEPT instruction not supported\n"); 
        return false; 
    }

    pr_info("KVX: EPT support verified\n"); 

    if (ept_vpid_cap & EPT_CAP_2MB_PAGES)
        pr_info("KVX: EPT 2MB large pages supported\n");
    
    if (ept_vpid_cap & EPT_CAP_1GB_PAGES)
        pr_info("KVX: EPT 1GB large pages supported\n");
        
    if (ept_vpid_cap & EPT_CAP_AD_FLAGS)
        pr_info("KVX: EPT accessed/dirty flags supported\n");
    
    return true;
}

struct ept_context *kvx_ept_context_create(void)
{
    struct ept_context *ept; 

    ept = kzalloc(sizeof(*ept), GFP_KERNEL); 
    if(!ept)
    {
        pr_err("KVX: Failed to allocate EPT context\n"); 
        return ERR_PTR(-ENOMEM); 
    }

    /*allocate root PML4 , 4kb page-aligned, zeroed*/ 
    ept->pml4 = (ept_pml4_t *)__get_free_page(GFP_KERNEL | __GFP_ZERO); 
    if(!ept->pml4)
    {
        pr_err("KVX: Failed to allocate EPT PML4 table\n"); 
        kfree(ept); 
        return ERR_PTR(-ENOMEM); 
    }
    ept->pml4_pa = virt_to_phys(ept->pml4); 

    ept->memtype = EPTP_MEMTYPE_WB;

    /*A/D flags disabled for now */ 
    ept->ad_enabled = false; 

    ept->eptp = CONTRUCT_EPTP(ept->pml4_pa, ept->memtype, ept->enable_ad); 

    memset(&ept->stats, 0, sizeof(ept->stats)); 

    spin_lock_init(&ept->lock); 

    pr_info("KVX : EPT context created, PML4 PA=0x%llx, EPTP=0x%llx\n", 
            ept->pml4_pa, ept->eptp); 

    return ept; 
}

static void kvx_ept_free_table(void *table_va, int level)
{
    ept_entry_t *entries = (ept_entry_t *)table_va; 
    int i; 

    if(level == 1)
    {
        free_page((unsigned long)table_pa); 
        return; 
    }

    for(i = 0; i < EPT_ENTRIES_PER_TABALE; i++)
    {
        ept_entry_t entry = entries[i]; 

        /*skip empty entries */ 
        if(!(entry & EPT_READ_ACCESS))
            continue; 

        /*check if this is a large page */ 
        if(entry & EPT_PAGE_SIZE)
            continue; 

        uint64_t child_pa = entry & EPT_ADDR_MASK; 

        void *child_va = phys_to_virt(child_pa); 

        kvx_ept_free_table(child_va, level, -1); 
    }

    free_page((unsigned)table_va);
}

void kvx_ept_context_destroy(struct ept_context *ept)
{
    if(!ept)
        return; 

    if(ept->pml4)
    {
        kvx_ept_free_table(ept->pml4, 4); 
        ept->pml4 = NULL; 
        ept->pml4_pa = 0; 
    }

    pr_info("KVX: EPT context destroyed (mapped %llu bytes)\n", 
            ept->stats.total_mapped); 

    kfree(ept); 
}


