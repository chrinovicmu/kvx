#vm_lanucher.s 
#
#this file contains the vmx transition code. 
#it is reposible for: 
#   - loading guest gneral purpost registers 
#   - executing VM-entry (VMLAUNCH / VMRESUME)
#   - regainning control on VM-exit 

# This code runs in kernel mode, with interrupts disabled or controlled,
# and must obey the System V AMD64 ABI where applicable.



#   - regainning control on VM-exit 

# This code runs in kernel mode, with interrupts disabled or controlled,
# and must obey the System V AMD64 ABI where applicable.


.globl kvx_vmentry_asm 
.globl kvx_vmexit_handler 

# streucture offsets (match struct guest_regs layout)

.set VCPU_RAX, 0
.set VCPU_RBX, 8
.set VCPU_RCX, 16
.set VCPU_RDX, 24
.set VCPU_RSI, 32
.set VCPU_RDI, 40
.set VCPU_RBP, 48
.set VCPU_R8,  56
.set VCPU_R9,  64
.set VCPU_R10, 72
.set VCPU_R11, 80
.set VCPU_R12, 88
.set VCPU_R13, 96
.set VCPU_R14, 104
.set VCPU_R15, 112

kvx_vmentry_asm:
    # at this point RDI contians the pointer to struct vcpu 
    #save host calle-Saved registers onto host stack
    push %rbp

    # load Guest GPRs from VCPU struct
    # We leave RAX for last as we need it for the base address
    mov VCPU_RBX(%rdi), %rbx
    mov VCPU_RCX(%rdi), %rcx
    mov VCPU_RDX(%rdi), %rdx
    mov VCPU_RSI(%rdi), %rsi
    mov VCPU_RBP(%rdi), %rbp
    mov VCPU_R8(%rdi),  %r8
    mov VCPU_R9(%rdi),  %r9
    mov VCPU_R10(%rdi), %r10
    mov VCPU_R11(%rdi), %r11
    mov VCPU_R12(%rdi), %r12
    mov VCPU_R13(%rdi), %r13
    mov VCPU_R14(%rdi), %r14
    mov VCPU_R15(%rdi), %r15

    mov VCPU_RAX(%rdi), %rax 
    mov VCPU_RDI(%rdi), %rdi #after this , we lose th vcpu pointer in RDI

    #.enter guest 
    #if this is the first time , use VMLAUNCH, otherwiaw use VMRESUME. 
    vmlaunch 
    vmresume 

    #if we reach here, VMLAUNCH/VMRESUME failed to start 
    pop %rbp 
    ret 


