# WhiteHat League 1 - Demon CTF [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
Sanity Check Write-Up - 출제자 풀이
-----------------------------------

## Introduce
* Author : 박광호 ([debukuk](http://debu.kr/))
* Field  : Misc
* E-Mail : debukuk154@gmail.com
* Date   : 2017-09-12

## Intention
* hex decoding을 할 수 있는가?
* url decoding을 할 수 있는가?
* rot13을 할 수 있는가?

* 플래그 형식은 **Demon{...}**

## Solve
`797661722b2b2b2b2b2532332a2b522b562b422b62632b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b73[...]b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2<br>`
 <br>
위와 같이 hex값으로 보이는 데이터들이 있다.<br>
 <br>
그래서 hex 디코딩을 하였다.<br>
 <br>
`%23*+R+V+B+bc++++++++[...]++++++++++++++++++++%7E9%0A+++6++++20++++++%3E+ERGHEA++++++++++++++++++++++`<br>
 <br>
%23 %7E 이렇게 %+hex가 있는 걸 보니 url encoding 된 데이터라고 생각된다.<br>
 <br>
이상한 문자열들이 많이 나왔다.<br>
 <br>
뭔가 rot13으로 꼬아논거 같아서 rot13을 돌려보았다. <br>
rot13을 돌렸더니 값이 정상적으로 보였다..<br>
<br>
### 플래그 획득
나온 데이터들중에서 opcode를 보면서 잘 맞춰보면 `FLAG{048443ba0d0e73cadbcec7925a9c4131}`가 된다.<br>
<br>
Flag: FLAG{048443ba0d0e73cadbcec7925a9c4131}<br>