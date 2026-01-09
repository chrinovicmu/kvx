#include <cerrno>
#include <linux/kthread.h> 
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/slab.h>     
#include <linux/vmalloc.h> 
#include <stddef.h>
#include <stdint.h>
#include <vmx.h>
#include <vm.h>
#include <utils.h>

extern void kvx_vmentry_asm(struct guest_regs, int launched); 

static u64 kvx_op_get_uptime(struct kvx_vm *vm)
{
    if (!vm) return 0;
    return ktime_to_ns(ktime_get()) - vm->stats.start_time_ns;
}

static void kvx_op_print_stats(struct kvx_vm *vm)
{
    pr_info("KVX [%s] Stats: Exits=%llu, CPUID=%llu, HLT=%llu\n",
            vm->vm_name, vm->stats.total_exits, 
            vm->stats.cpuid_exits, vm->stats.hlt_exits);
}

static void kvx_op_dump_regs(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu = vm->vcpus[vcpu_id];
    if (!vcpu) return;
    
    pr_info("KVX [%s] VCPU %d RIP: 0x%llx RSP: 0x%llx\n",
            vm->vm_name, vcpu_id, vcpu->regs.rip, vcpu->regs.rsp);
}

static const struct kvx_vm_operations kvx_default_ops = {
    .get_uptime  = kvx_op_get_uptime,
    .print_stats = kvx_op_print_stats,
    .dump_regs   = kvx_op_dump_regs,
};

int kvx_vm_allocate_guest_ram(struct kvx_vm *vm, uint64_t size, uint64_t gpa_start)
{
    struct guest_mem_region *region; 
    uint64_t num_pages; 
    uint64_t i; 
    struct page *page; 
    uint64_t gpa; 
    uint64_t hpa; 
    int ret; 

    if(!vm || !vm->ept)
        return -EINVAL; 

    size = PAGE_ALIGN(size); 
    num_pages = size / PAGE_SIZE;

    pr_info("KVX: Allocating %llu pages (%llu MB) of guest RAM at GPA 0x%llx\n",
            num_pages, size / (1024 * 1024), gpa_start);

    region = kzalloc(sizeof(*mr), GFP_KERNEL); 
    if(!region)
        return -ENOMEM;

    region->pages = kzalloc(num_pages * sizeof(struct page*), GFP_KERNEL); 
    if(!region->pages)
    {
        kfree(region); 
        return -ENOMEM; 
    }

    region->gpa_start = gpa_start; 
    region->size = size;
    region->num_pages = num_pages; 
    region->flags = EPT_RWX;

    for(i = 0;i < num_pages; i++ )
    {
        page = alloc_page(GFP_KERNEL | __GFP_ZERO); 
        if(!page)
        {
            pr_err("KVX: Failed to allocate page %llu/%llu\n", 
                   i + 1, num_pages); 
            ret = -ENOMEM; 
            goto _cleanup; 
        }
        region->pages[i] = page; 
        gpa = gpa_start + (i * PAGE_SIZE); 
        hpa = page_to_phys(page); 

        ret = kvx_ept_map_page(vm->ept, gpa, hpa, EPT_RWX); 
        if(ret < 0)
        {
            pr_err("KVX: Failed tp map page at GPA 0x%llx\n", gpa); 
            __free_page(page); 
            goto _cleanup; 
        }
        
        /*progress indicator for every 256MB*/
        if (i > 0 && (i % (256 * 1024 * 1024 / PAGE_SIZE)) == 0) 
        {
            pr_info("KVX: Mapped %llu MB...\n",
                    (i * PAGE_SIZE) / (1024 * 1024));
        }

    }

    region->next = vm->mem_regions; 
    vm->mem_regions = region; 
    vm->total_guest_ram += size; 

    pr_info("KVX: Successfully allocated and mapped guest RAM\n");
    
    kvx_ept_invalidate_context(vm->ept);
    
    return 0;
 
}

void kvx_vm_free_guest_mem(struct kvx_vm)
{
    struct guest_mem_region *region;
    struct guest_mem_region *next; 
    uint64_t i; 

    if(!vm)
        return; 

    region = vm->mem_regions; 
    while(!region)
    {
        next = region->next; 
        if(region->pages)
        {
            for(i = 0; region->num_pages; i++)
            {
                if(region.pages[i])
                    __free_page(region.pages[i]); 
            }
            kfree(region->pages); 
        }
        kfree(region); 
        region = next; 
    }

    vm->mem_regions = NULL; 
    vm->total_guest_ram = 0; 
}

struct kvx_vm * kvx_create_vm(int vm_id, const char *vm_name, 
                              uint64_t ram_size)
{
    struct kvx_vm *vm;
    struct vcpu *vcpu; 

    vm = kzalloc(sizeof(struct kvx_vm), GFP_KERNEL); 
    if(!vm)
    {
        pr_err("KVX: Failed to allocate VM header\n"); 
        return NULL; 
    }

    vm->vm_id = vm_id; 
    vm->state = VM_STATE_CREATED; 
    vm->max_vcpus = KVX_MAX_VCPUS; 
    vm->online_vcpus = 0; 
    vm->ops = &kvx_default_ops; 

    if(vm_name)
        strscpy(vm->vm_name, vm_name, sizeof(vm->vm_name)); 
    else
        snprintf(vm->vm_name, sizeof(vm->vm_name), "vm-%d", vm_id); 
    spin_lock_init(&vm->lock); 

    if(!kvx_ept_check_support())
    {
        pr_err("KVX: EPT not supported on ths CPU\n"); 
        goto _out_free_vm; 
    }

    vm->ept = kvx_ept_context_create(); 
    if(IS_ERR(vm->ept))
    {
        pr_err("KVX: Failed to create EPT context\n"); 
        vm->ept = NULL; 
        goto _out_free_vm; 
    }

    pr_info("KVX: Created EPT context for VM %d (EPTP=0x%llx)\n",
            vm_id, vm->ept->eptp);


    if(ram_size > 0)
    {
        ret = kvx_vm_allocate_guest_ram(vm, ram_size, 0x0); 
        if(ret < 0)
        {
            pr_err("KVX: Failed to allocate guest RAM\n"); 
            goto _out_free_ept; 
        }
        pr_info("KVX: Allocated %llu MB guest RAM\n"); 
    }

    vm->vcpus = kcalloc(vm->max_vcpus, sizeof(struct vcpu*), GFP_KERNEL); 
    if(!vm->vcpus)
    {
        pr_err("KVX: Faild to allocate VCPU array\n"); 
        goto _out_free_memory; 
    }

    vm->state = VM_INITIALIZED; 

    pr_info("KVX: VM '%s' (ID: %d) created with %llu MB RAM\n", 
            vm->vm_name, vm->vm_id, (ram_size >> 20)); 

    return vm;

_out_free_memory:
    kvx_vm_free_guest_mem(vm); 
_out_free_ept:
    if(!vm->ept)
    {
        kvx_ept_context_destroy(vm->ept); 
        vm->ept = NULL; 
    }
_out_free_vm:
    kfree(vm); 
    return NULL; 
}

void kvx_destroy_vm(struct kvx_vm *vm)
{
    int i; 

    if(!vm)
        return; 

    pr_info("KVX: Destroying VM '%s' (ID: %d)\n", vm->vm_name, vm->vm_id); 

    /*stop and free all vcpus */ 
    if(vm->vcpus)
    {
        for(i = 0; i < vm->max_vcpus; i++)
        {
            if(vm->vcpus[i])
            {
                /*if VCPU has runnning thread, stop it first.*/
                if(vm->vcpus[i]->host_task)
                    kthread_stop(vm->vcpus[i]->host_task); 

                kvx_free_vcpu(vm->vcpus[i]);
                vm->vcpus[i] = NULL; 
            }
        }
        kfree(vm->vcpus); 
    }

    kvx_vm_free_guest_mem(vm); 
    if(vm->ept)
    {
        kvx_ept_context_destroy(vm->ept); 
        vm->ept = NULL; 
    }

    kfree(vm); 

    pr_info("KVX: VM destruction complete.\n"); 
}

int kvx_vm_copy_to_guest(struct kvx_vm *vm, int gpa, const void *data, int size)
{
    struct guest_mem_region *region; 
    uint64_t region_offset; 
    uint64_t page_index;
    uint64_t page_offset; 
    uint64_t bytes_to_copy; 
    const uint8_t *src = (const uint8_t *)data; 
    uint8_t *page_va; 
    size_t copied = 0; 

    if(!vm || !data || size == 0)
        return -EINVAL; 

    region = vm->mem_regions; 

}
/**
 * kvx_vm_add_vcpu - Creates and pins a VCPU to a specific host CPU.
 * @vm: The parent virtual machine struct.
 * @vcpu_id: The index of the VCPU (0 to vm->max_vcpus - 1).
 * @target_host_cpu: The logical ID of the host CPU to pin to.
 * * Returns 0 on success, < 0 on failure.
 */
int kvx_vm_add_vcpu(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu; 
    int ret = 0; 

    spin_lock(&vm->lock); 

    /*checking against 0 becasue the vcpu_id 0 
     * is reserved for the host if vpid used 
     * */ 
    if(vcpu_id <= 0 || vcpu_id >= vm->max_vcpus || vm->vcpus[vcpu_id] != NULL)
    {
        pr_err("KVX: Invalid or already existing VCPU ID %d.\n", vcpu_id); 
        ret = -EINVAL; 
        goto _unlock_vm; 
    }

    /*allocate and initilize struct vcpu */ 
    vcpu = kvx_vcpu_alloc_init(vm, vcpu_id); 
    if(!vcpu)
    {
        ret = -ENOMEM; 
        goto _unlock_vm; 
    }

    /*store vcpu in the VM 's array */ 
    vm->vcpus[vcpu_id] = vcpu; 

    /*set stack pointer to top of VM RAM */
    vcpu->regs.rsp = vm->guest_ram_size; 

    vcpu->state = VCPU_STATE_INITIALIZED; 
    vm->online_vcpus++; 

    PDEBUG("KVX: VCPU %d for VM %d successfully pinned to Host CPU %d", 
           vcpu_id, vm->vm_id, vcpu->target_cpu_id);

_unlock_vm: 
    spin_unlock(&vm->lock); 
    return ret; 
}

static int kvx_vcpu_loop(void *data)
{
    struct vcpu *vcpu = (struct vcpu*)data; 

    /*secure context: pin to specific CPU assigned during 'add_cpu' */ 
    kvx_vcpu_pin_to_cpu(vcpu, vcpu->target_cpu_id); 

    /*acitvate hardware: load the vmcs on this specific core */
    if(_vmptrld(vcpu->vmcs_pa))
    {
        pr_err("KVX: VMPTRLD failed on CPU %d\n", vcpu->target_cpu_id); 
        return -1; 
    }

    if(kvx_init_vmcs_state(vcpu))
        return -1; 


    while(!kthread_should_stop())
    {
        kvx_vmentry_asm(vcpu->regs, vcpu->launched); 

        /*if we are here, it means:
        * handler_vmexit() returned 0 (requesred stop)
        * VMLAUNCH/VregionESUME failed (hardware error)
        */ 
        if(vcpu->launched)
        {
            uint64_t error = __vregionead(VMCS_INSTRUCTION_ERROR_FIELD);
            if(error != 0)
            {
                pr_err("KVX: Hardware Error: %llu\n", error); 
                break; 
            }
        }
        vcpu->launched = 1; 
    }

    __vmclear(vcpu->vmcs_pa); 
    return 0; 
}

int kvx_run_vm(struct kvx_vm *vm, int vcpu_id)
{
    struct vcpu *vcpu; 

    if(vcpu_id >= vm->max_vcpus || vm->vcpus[vcpu_id] == NULL)
        return -EINVAL; 

    vcpu = vm->vcpus[vcpu_id]; 
    vcpu->launched = 1; 

    /*spawn kthread to run the exexution loop */ 
    vcpu->host_task = kthread_run(kvx_vcpu_loop, vcpu, "kvx_vm%d_vcpu%d", vm->vm_id, vcpu_id); 
    if(IS_ERR(vcpu->host_task))
    {
        pr_err("KVX: Failed to spawn kthread for VCPU %d\n", vcpu_id);
        return PTR_ERR(vcpu->host_task); 
    }

    return 0;
}


