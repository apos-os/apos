megs: 32
romimage: file=bochs/bios/BIOS-bochs-latest
vgaromimage: file=bochs/bios/VGABIOS-elpin-2.40
floppya: 1_44="kernel.img", status=inserted
boot: a
log: bochsout.txt
mouse: enabled=0
clock: sync=realtime
cpu: ips=1000000
display_library: term
gdbstub: enabled=1, port=1234, text_base=0, data_base=0, bss_base=0
parport1: enabled=1, file="log.txt"
