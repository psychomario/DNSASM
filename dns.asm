BITS 64
GLOBAL _start
SECTION .text
_start:
    pop rax
    cmp rax, 3
    jne exit
    pop rax ;file name
    pop rax ;DNS server addr
loop:
    xor dl, dl
    mov byte dl, [rax] ;pull byte
    sub dl, 0x30 ;sub 30
    add bl, dl
    inc rax ;inc ptr
    inc rax
    cmp rax, [rsp] ;are we done?
    je ipfin
    dec rax
    cmp byte [rax], '.'
    je newbyte
    imul rbx, 10
    jmp loop
newbyte: ;next octet
    inc rax ;skip .
    shl r8, 8
    cmp rbx, 255
    jge exit
    add r8, rbx
    xor rbx, rbx
    jmp loop
ipfin:
    shl r8, 8
    add r8, rbx ;r8 now contains packed ip
    mov [packedip], r8
    xor rax, rax
    xor rbx, rbx
    pop rax ;addr of domain
    mov rdx, rax ;backup
    pop rbx
    pop rbx
    dec rbx ;end NULL
    xor rcx, rcx
qryloop: ;count and push all section lengths delim .
    inc rcx
    inc rax
    cmp byte [rax], '.'
    jne next
    push rcx
    xor rcx, rcx
next:
    cmp rax, rbx
    jne qryloop
    dec rcx
    push rcx
prev: ;go back and pop off to replace each .
    xor rcx, rcx
    cmp byte [rax], '.'
    jne isend
    pop rcx
    mov [rax], cl
isend:
    dec rax
    cmp rax, rdx
    jne prev
qryfin: ;begin to craft full packet
    pop rcx
    dec rax
    mov [rax], cl
    mov r9, rax ;r9 now contains ptr to question name
    mov rsi, queryheader
    mov rdi, fullpacket
    cld
    mov rcx, 6 ;queryheader len /2
    rep movsw ;12 bytes queryheader -> fullpacket
    add word [fullpacketlen], 8
    xor rcx, rcx
countquery: ;get question name length
    inc rcx
    inc r9
    cmp byte [r9], 0x00
    jne countquery
    sub r9, rcx
    add [fullpacketlen], rcx
    mov rsi, r9
    cld
    rep movsb ;rcx bytes question name -> fullpacket
    inc rdi
    mov rsi, qsectionpost
    cld
    mov rcx, 2
    rep movsw ;4 bytes qsectionpost -> fullpacket
    add word [fullpacketlen], 9 ;postamble and stuff
    ;fullpacket now complete at fullpacket
    ;length in fullpacketlen
    ;packed ip in packedip
    xor rax, rax
    xor rbx, rbx
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9

    mov rax, 41 ;SYS_SOCKET
    mov rdi, 2 ;AF_INET
    mov rsi, 2 ;SOCK_DGRAM
    mov rdx, 0
    syscall ;rax is now fd for udp sock

    mov rdi, rax ;sockfd
    mov rax, 42 ;SYS_CONNECT
    mov word [sockaddr], 0x02 ;AF_INET
    mov word [sockaddr+2], 0x3500 ;port 53 (dns)
    mov rsi, [packedip]
    bswap esi
    mov dword [sockaddr+4], esi
    mov rsi, sockaddr
    mov rdx, 16
    syscall ;rdx is now fd for connected udp sock

    mov rax, 44 ;SYS_SENDTO
    mov rsi, fullpacket ;*buf
    mov rdx, [fullpacketlen] ;len
    xor rcx, rcx ;flags
    xor r8, r8 ;dest_addr
    xor r9, r9 ;addrlen
    syscall
    ;packet sent now, response coming

    mov rax, 45 ;SYS_RECVFROM
    mov rsi, fullpacket ;*buf
    mov rdx, 512 ;packetlen
    xor rcx, rcx ;flags
    xor r8, r8 ;address
    xor r9, r9 ;addrlen
    syscall

    xor rax, rax
    xor rbx, rbx
    xor rsi, rsi
    xor rdx, rdx
    xor r8, r8
    xor r9, r9

    mov rax, fullpacket
    add rax, 6 ;Transaction ID, Flags, question count
    mov bl, [rax+1] ;wrong, but we're not gonna get <255 responses are we
    add rax, 6 ;answer, auth rr, additional rr
    mov rcx, [fullpacketlen]
    sub rcx, 8
    sub rcx, 4 ;rcx is the length of the query
    add rax, rcx
    ;rax now at first answer
    
    mov dl, bl ;number of responses
    mov r12, rdx
    mov r8, rax ;buffer address
    xor rax, rax
nextqry:
    add r8, 12 ;skip to next response
    mov r9, 4 ;for octet loops
    mov byte [octet+3], '.' ;seperator
octet4:
    mov al, [r8] ;first octet
    mov r11, octet ;each char storage
    add r11, 2 ;start at LSB
octdig:
    xor r10, r10
    cmp ax, 10 ;< 10 so don't divide
    jl lt10
sub10:
    sub ax, 10 ; -10 until < 10
    inc r10
    cmp ax, 10
    jge sub10
lt10:
    add al, 0x30 ; make ascii number
    mov [r11], al ;put in octet storage
    dec r11 ;move up towards MSB
    mov rax, r10
    cmp r11, octet
    jge octdig ;continue for 3 chars
    inc r11 ;r11 at start of octet
    inc r8
    cmp r9, 1
    jne skip
    mov byte [octet+3], 0x0a ;if last octet, end in newline not '.'
skip:
    xor rax, rax
    xor rsi, rsi
    xor rdx, rdx
    cmp byte [r11], 0x30 ;remove trailing zeros
    jne nozero
    inc r11
    cmp byte [r11], 0x30 ;up to twice
    jne nozero
    inc r11
nozero:
    mov rax, 1
    mov rdi, 1
    mov rsi, r11
    mov rdx, 4
    syscall ;print out this octet
    dec r9
    cmp r9, 0
    jne octet4 ;next octet
    dec r12
    cmp r12, 0
    jg nextqry ;next response
    call exit
exit:
    xor rax, rax
    add rax, 60
    xor rdi, rdi
    syscall
SECTION .data
queryheader: ;8 bytes
    db 0x13,0x37 ;ID
    db 0x01,0x00   ;QR Opcode AA TC RD RA -- recursion bit set
    db 0x00,0x01   ;QDCOUNT
    db 0x00,0x00   ;ANCOUNT
    db 0x00,0x00   ;NSCOUNT
    db 0x00,0x00   ;ARCOUNT
qsectionpost: ;4 bytes
    db 0x00,0x01
    db 0x00,0x01
SECTION .bss
packedip:
    resb 4
fullpacketlen:
    resb 8
fullpacket:
    resb 512 ;general consensus for udp max size
sockaddr:
    resb 16
octet:
    resb 4
