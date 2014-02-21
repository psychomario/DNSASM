default:
	nasm -f elf64 dns.asm -o dns.o && ld dns.o -o dns
clean:
	rm dns.o dns
