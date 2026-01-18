cmd_/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o :=  gcc-12 -Wp,-MMD,/home/chrinovic/Workspace/Projects/relm/src/.vmx_asm.o.d -nostdinc -I/usr/src/linux-headers-6.1.0-42-common/arch/x86/include -I./arch/x86/include/generated -I/usr/src/linux-headers-6.1.0-42-common/include -I./include -I/usr/src/linux-headers-6.1.0-42-common/arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I/usr/src/linux-headers-6.1.0-42-common/include/uapi -I./include/generated/uapi -include /usr/src/linux-headers-6.1.0-42-common/include/linux/compiler-version.h -include /usr/src/linux-headers-6.1.0-42-common/include/linux/kconfig.h -D__KERNEL__ -fmacro-prefix-map=/usr/src/linux-headers-6.1.0-42-common/= -D__ASSEMBLY__ -fno-PIE -m64 -DCC_USING_FENTRY -g  -DMODULE  -c -o /home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o /home/chrinovic/Workspace/Projects/relm/src/vmx_asm.S  ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --orc --retpoline --rethunk --sls --static-call --uaccess   --module /home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o

source_/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o := /home/chrinovic/Workspace/Projects/relm/src/vmx_asm.S

deps_/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o := \
  /usr/src/linux-headers-6.1.0-42-common/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /usr/src/linux-headers-6.1.0-42-common/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \

/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o: $(deps_/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o)

$(deps_/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o):

/home/chrinovic/Workspace/Projects/relm/src/vmx_asm.o: $(wildcard ./tools/objtool/objtool)
