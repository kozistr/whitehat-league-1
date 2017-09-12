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
> 먼저 PE 부터 봐 보자
-   시그니처 검색으로 UPX 0.89.6 - 1.02 / 1.05 - 2.90 -> Markus & Laszlo 탐지
-	기존 segments 이외에 .asdf, .zero0(0x040F000) 섹션이 보임
-	TLS 섹션 존재
-	Binary Entropy 상으로 packed, EP상으론 not packed
-	주어진 바이너리 크기는 48kb, 그런데 asdf 섹션에 거대한? 더미 같은 것을 빼면 실제 코드 사이즈는 20kb 후반 추정
-	아키텍쳐는 win32 바이너리, API import 를 보니 사실상 쓰인 API 가 거의 없다.
-   아마 어딘가에서 API Logger 같은 부분이 있을거라 추측해봄
