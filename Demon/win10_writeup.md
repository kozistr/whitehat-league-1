# WhiteHat League 1 - Demon CTF [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
Win10 Write-Up - 출제자 풀이
-----------------------------------

## Introduce
* Author : 김형찬 ([zer0day](http:/zer0day.tistory.com))
* Field  : Reverse Engineering
* E-Mail : kozistr@gmail.com
* Date   : 2017-09-12

## Intention
* 전체적인 컨셉으로는 여러 가지 보호 기법 및 난독화가 적용된 프로그램 분석
* 프로그램 역공학 방지를 위한 여러 **안티-리버싱 기법**들을 우회
* 그런데 아마 우회가 ~~좀~~ 빡실?테니
* 결론은 **최소한**의 동적분석과 정적분석을 통한 분석
* 플래그 형식은 **Demon{...}**

## Solve
* 본격 초심 + 의식의 흐름 기법 풀이

### 1. Static Analysis
> 1. 먼저 PE 부터 봐 보자
-   시그니처 검색으로 UPX 0.89.6 - 1.02 / 1.05 - 2.90 -> Markus & Laszlo 탐지
-	기존 segments 이외에 .asdf, .zero0(0x040F000) 섹션이 보임
-	TLS 섹션 존재
-	Binary Entropy 상으로 packed, EP 상으론 not packed
-	주어진 바이너리 크기는 48kb, 그런데 asdf 섹션에 거대한? 더미 같은 것을 빼면 실제 코드 사이즈는 20kb 후반 추정
-	아키텍쳐는 win32 바이너리, API import 를 보니 사실상 쓰인 API 가 거의 읎다
-   아마 어딘가에서 API Logger 같은 부분이 있을거라 추측해봄, ~~아님 말고..~~
> 2. 정리 쪼까 해보면
- upx 는 뭔가 아녀 보이고, custom packer 적용 가능성도 보이지만 아닌거 같다
- 비슷한 성격을 띄는 게 vmp 정도? (*흠.. MessageBoxA가 보였었나...*)

실제로 열어보면 바이너리는 packer로 packed 되지 않은거 같고
EP(0x040473C) 부분이 MSCV 컴파일러 EP 부분과 비슷한데 뭔가 프로텍팅 되어있는 거 같다.
아마 *VMProtect 2.x*을 사용한 듯 ㅇㅇ... 는 아닌거 같고 fake signature 같따
~~아 배고파~~

> 3. TLS 킾 고잉
- 음.. sub_4042CE(main) 여기가 메인 함수다.
어떻게 찾았냐? start 따라가보셈 고럼 main 있어야할 곳에 main 있당께
- 아까 TLS 섹션도 존재했는데 이거는 특정 버전의 vmp 프로텍팅 옵션으로 생긴 TLS가 아닌거 같다. (~~고놈의 프로텍터 미련...~~)
간략하게 TLS 섹션 분석한 걸 나열하면
1. **API Logger** 존재 (kernel32.dll)
TLS 초반에 PEB->LDR 가서 궁시렁 거리는 부분 있 ㅇㅇ
2. 매 API 실행 전까지 **API Address Encrypt/Decrypt**
**seed(100)** 해서 각 API 끼리 xor xor xor xor ... 함, 고러고 API call 직전 즘에 또 돌려서 주소 복원데스
3. Anti-Dump 및 여러 기법 적용됨 (고런데 Anti-Injection 이 없다! 아직 모른다 ㅁㄴㅇㄹ)

> 4. 킾킾킾 고잉
> ![킾 고잉](https://github.com/kozistr/whitehat-league-1/blob/master/image/gopher.png)
- main 함수를 보면, 초반부터 장난질이다;;
- top exception handler 걸어두고 divide by zero 예외를 일부러 발생 시키고, 그 등록한 핸들러에서 EIP 를 몇 바이트 점프해 버리기!
요로코롬 따라가다 보면 뭐 몇 가지를 세팅하는데
- **blowfish key 도 세팅**하고 **crc64** 에 대한 **poly 값**도 세팅을 한다.
- (어떻게 알았냐면 crc64 알고리즘은 보면 뙇이고 blowfish는 krypton.py 라는 ida **플러그인** 하고 PeID의 **플러그인**)
API 가 다 숨어있고 루틴도 다 깨져서 더 이상 동적 정보 없이 진행에 무리데스...

> 5. 후.. 동적 분석 하고 왔다.. (질문은...안받고 진행함)
- 갔다왔는데 콘솔에 쓰는 문자열들도 다 암호화가 되어 있고 API도 다 암호화가 되어 있는데, 다행이 API 이름들은 **xor 0xcc** 로 복호화가 된다.
- 콘솔에 쓰이는 문자열들은 그 아까 blowfish key 생성도 한다 했는데 그 키를 기반으로 **복호화 작업**을 한다.
- 그 주변 살펴보면 뭔가 키 인증 뭐시기 루틴이 있는데 정리하면 아래와 같다.
<pre>
    <code>
        key는 총 16 bytes. let 첫 8글자를 A, let 뒤 8 글자를 B
        crc64(A + 임의의 8바이트) = 특정해쉬, A 의 각 문자들의 int 합 0x2dc, blowfish_decrypt(B, key) = 값
        * crc64 table 를 생성하는 poly 값은 0xcafebebedeadbeef
        * blowfish key 를 구성할 때 쓰이는 값은 blowfish algorithm s-box 배열 부분 앞에 ulong 2개 값 (기억으론..?)
        * 임의의 8바이트라는게 고거시... rand()%256 으로 gen 이 되는디. 아까 봤듯이 **seed(100)** 뙇
    </code>
</pre>
- crc64 테이블 및 엘고뤼듬에 대해선 한 번에 64bit len을 가지는 값들로 이뤄져서 **설계상 reverse 를 할 수가 있다.**
- 또한 stream 특성 때문에 **약간의 brute-force와 함께 un-crc64** 도 가능하다
이제 풀러 가자~ 아래로~

### 2. Dynamic Analysis ~~그냥 멋있어 보이는 단어 써 봤다 다이눼~믹~~
프로그램을 걍 실행해보면 Input : 이란 문자열이 콘솔에 뜨는데 뭘 입력하면 Wrong :( 가 뜨고 몇 초뒤에 종료가 된다.
> ![실행](https://github.com/kozistr/whitehat-league-1/blob/master/image/just-run.png)
~~Anti-Reversing Bypass 를 하 다는 짓은 귀찮으니.. 최대한 미루자!~~
1. 일단 입출력과 딜레이가 있다는 건 printf, scanf 가 없으니 *WriteConsoleA, ReadConsoleA, Sleep* 이 숨어져 있다는 거고
2. TLS 에서 얻은 정보로 찾아보면 입출력 부분을 찾을 수 있었다. (**고거 근처에 핵심 연산도 있었따! 요거 완전 9reat**)
3. IDA나 다른 디버깅 툴의 안티디버깅 bypass 플러그인 옵션을 다 키고 진행했는데도 여러 부분에서 막혀서 일단 **API 정보**를 얻은 것 만으로 다시 정적 진행을 해야겠다.
음.. 사용된 기법들 찾은 것도 알아냈지만 **여백이 부족해 생략**을… 읍읍  **9reat**
- 다시 3인칭 제작자 관점서 서술하자면 아마 못 봤을만 한 기법 넣어버렸따리

> 아 하나 추가하자면 문제 이름이 Win10인 이유를 알아낸 거 같다!
고거슨 Win10에서만 실행이 가능한데 이유가 OutputDebugString 을 사용해서 OS 를 Detect 하는 부분이 있따.<br/>
디버깅 중이 아닐 때 임의의 인자와 함께 실행을 하면 **win10, xp 에서는 1, vista, 7 에서는 0을 리턴**한다.<br/>
그런데 이 프로그램은 win xp 비호환으로 컴파일 되서 only for win10 이 되는거 같다.~~아님 말~고 ㅎㅎㅎㅎㅎㅎ~~<br/>

(위 5번으로 올라가셈) (다보고 내려오셈)
> 해당 스크립트를 돌리면 아래와 같은 화면을 볼 수 있다.<br/>
> ![실행](https://github.com/kozistr/whitehat-league-1/blob/master/image/correct.png)<br/>
(위 사진과 경로가 다른 건 무시해 주자 ㅎ)<br/>

해당 문장과 함께 2.5초 뒤에 플그램이 꺼지면서 프로그램과 같은 폴더에 asdf란 파일이 생기는데,
hexeditor 로 magic number 를 보면 7z 파일이라 카더라... 압축풀면 아래와 같은 화면을 볼 수 있따.
> 엌 참고로 파일은 rc6 으로 encrypt 되어 있었나 부다.. 마지막에 rc6 decrypt 하는 듯 ㅇㅅㅇ

> ![끗](https://github.com/kozistr/whitehat-league-1/blob/master/image/done.png)
쨕쨕쨕

### 3. Solver
<pre>
    <code>
import sys, string
from itertools import product
from multiprocessing.pool import Pool

from sage.all import *


def crc64table(table, poly):
    for i in range(256):
        crc = i
        for j in range(8):
            if crc & 1:
                crc >>= 1
                crc ^= poly
            else:
                crc >>= 1
        table[i] = crc


def crc64(str, crc_=0):
    crc = crc_
    for c in str:
        crc = table[(crc & 0xff) ^ ord(c)] ^ (crc >> 8)
    return long(crc)


# decrypt key  : 0x62, 0x6c, 0x65, 0x57, 0x46, 0x31, 0x73, 0x68, 0x42, 0x6c, 0x30, 0x77, 0x66, 0x69, 0x73, 0x68

# poly64 value : 0xcafebebedeadbeef                             # which is hidden(packed) in the program
# origin       : 0x62, 0x6c, 0x65, 0x57, 0x46, 0x31, 0x73, 0x68 # sum : 0x2dc
# salt         : 0xc0, 0x27, 0x40, 0xb8, 0xf6, 0x7a, 0xa6, 0xa9 # with rand() % 256

origin_salt = "0x62, 0x6c, 0x65, 0x57, 0x46, 0x31, 0x73, 0x68, 0xc0, 0x27, 0x40, 0xb8, 0xf6, 0x7a, 0xa6, 0xa9"
origin_salt = origin_salt.replace('0x', '').replace(',', '').replace(' ', '').decode('hex')

# Step 1 : Generating crc64 table with the specific poly64 value
table = [0] * 256
crc64table(table, 0xcafebebedeadbeef)

# Step 2 : Generating crc64 un-table
untable = [0] * 256
for i in range(256):
    untable[(crc64(chr(i)) & 0xffffffffffffffff) >> 56] = (crc64(chr(i)) & 0xffffffffffffffff)

org_crc = crc64(origin_salt)
print("[+] Original crc64 Value : " + hex(org_crc))

# Step 3 : reverse-crc64 with the known 8 bytes we've got from the 'rand() % 256'
for i in range(len(origin_salt) - 1, 8 - 1, -1):
    v = org_crc >> 56
    org_crc = ((org_crc ^ untable[v]) << 8) | (table.index(untable[v]) ^ ord(origin_salt[i]))

# Step (3-1) : Verifying crc64(origin)
tmp = ""
for j in origin_salt[:8]:  # origin
    tmp += j
    print("[*] pure value : " + hex(crc64(tmp)))

# Step (3-2) : Verifying reversed org_salt crc64
print("[+] Reversed crc64 : " + hex(org_crc))

assert org_crc == crc64(tmp)

# Stage 4 : uncrc64 process
N = 8   # number of string
M = MatrixSpace(GF(2), 64, N * 7)
V = VectorSpace(GF(2), 64)

nBF = 4

charset = string.lowercase + string.uppercase + string.digits  # a-zA-Z0-9

base = crc64("\x00" * N)

diffs = {}
for i in range(N):
    for j in range(7):
        key = [0] * N
        key[i] |= (1 << j)
        diffs[i, j] = crc64(''.join(map(chr, key))) ^ base

matrix = M()
for (i, j), vec in diffs.items():
    if i < nBF:
        continue
    column = i * 7 + j
    for row in range(64):
        matrix[row, column] = (vec & (1 << row)) >> row


diff_mas = org_crc ^ base


def uncrc64(first_charset):
    lst = [map(ord, l) for l in [first_charset] + [charset] * (nBF - 1)]

    for prefix in product(*lst):
        diff = diff_mas
        for i in range(nBF):
            for j in range(7):
                if prefix[i] & (1 << j):
                    diff ^= diffs[i, j]
                continue

        resvec = V([(diff & (1 << row)) >> row for row in range(64)])

        try:
            x = matrix.solve_right(resvec)
        except ValueError:
            continue

        s = [0] * N
        for i, v in enumerate(x):
            i, j = divmod(i, 7)
            if v or (i < nBF and prefix[i] & (1 << j)):
                s[i] |= (1 << j)

        if sum(s) == 0x2dc:
            key = ''.join(map(chr, s))
            if set(key).issubset(set(charset)):
                print("[+] Got :", key, hex(crc64(key)))


workers = 32

p = Pool(workers)
p.map(uncrc64, charset)

'''
[+] Original crc64 Value  : 0x9f6f42e2fcd96a45L
[*] pure value : 0x984241410bdfd52fL
[*] pure value : 0x35e5e5667de886e4L
[*] pure value : 0x30344dcd57116abbL
[*] pure value : 0xe779077e89711a14L
[*] pure value : 0xe485b0cec1d5cc9fL
[*] pure value : 0x282f073259c5bb51L
[*] pure value : 0x37eb8fa7887d710cL
[*] pure value : 0x38705a3e0b3ca4d3L
[+] Reversed crc64 : 0x38705a3e0b3ca4d3L
[+] Rank is 28
[+] Got :  bleWF1sh 0x38705a3e0b3ca4d3L
'''
    </code>
</pre>

