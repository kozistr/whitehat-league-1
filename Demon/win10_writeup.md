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

> 3. TLS 킾 고잉 ![킾 고잉](https://github.com/kozistr/whitehat-league-1/blob/master/image/gopher.png)
- 음.. sub_4042CE(main) 여기가 메인 함수다.
어떻게 찾았냐? start 따라가보셈 고럼 main 있어야할 곳에 main 있당께
- 아까 TLS 섹션도 존재했는데 이거는 특정 버전의 vmp 프로텍팅 옵션으로 생긴 TLS가 아닌거 같다. (~~고놈의 프로텍터 미련...~~)
간략하게 TLS 섹션 분석한 걸 나열하면
1. **API Logger** 존재 (kernel32.dll)
TLS 초반에 PEB->LDR 가서 궁시렁 거리는 부분 있 ㅇㅇ
2. 매 API 실행 전까지 **API Address Encrypt/Decrypt**
**seed(100)** 해서 각 API 끼리 xor xor xor xor ... 함, 고러고 API call 직전 즘에 또 돌려서 주소 복원데스
3. Anti-Dump 및 여러 기법 적용됨 (고런데 Anti-Injection 이 없다! 아직 모른다 ㅁㄴㅇㄹ)

> 4. 킾킾킾 고잉 ![킾 고잉](https://github.com/kozistr/whitehat-league-1/blob/master/image/gopher.png)
이제 main 함수를 보면, 초반부터 장난질이다;;
- top exception handler 걸어두고 divide by zero 예외를 일부러 발생 시키고, 그 등록한 핸들러에서 EIP 를 몇 바이트 점프해 버리기!
요로코롬 따라가다 보면 뭐 몇 가지를 세팅하는데
- blowfish key 도 세팅하고 crc64 에 대한 poly 값도 계산을 한다.
- (어떻게 알았냐면 crc64 알고리즘은 보면 뙇이고 blowfish는 krypton.py 라는 ida 플러그인 하고 PeID의 플러그인)
API 가 다 숨어있고 루틴도 다 깨져서 더 이상 동적 정보 없이 진행에 무리데스...
