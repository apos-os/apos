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
ata0-master: type=disk, path="hd1.img", mode=flat, cylinders=20, heads=16, spt=63
ata0-slave: type=disk, path="hd2.img", mode=flat, cylinders=20, heads=16, spt=63
ata1-master: type=disk, path="hd3.img", mode=flat, cylinders=20, heads=16, spt=63
ata1-slave: type=disk, path="hd4.img", mode=flat, cylinders=20, heads=16, spt=63
