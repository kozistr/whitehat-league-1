# WhiteHat League 1 - Demon CTF [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
OCR Write-Up - 출제자 풀이
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
## 2.1 초기 분석
코드는 간단하게 preg_match로 url인자가 http:로 시작하는지 검사한다. 그리고 url 변수로 파일을 불러오고 filename 변수에 /img/ + md5(url + 랜덤글자(a,b,c)) + .jpg를 넣어준다.<br>
여기가 취약점이 터질 수 있다고 생각할 수 있는 부분인데 file_put_contents 함수로 불러온 데이터의 값을 로컬에 저장한다.<br>
그리고 ocr 함수를 통해서 이미지안의 문자를 읽어내고 json_encode로 표시해준다.<br>
이후에는 파일이 서버에 계속 존재하면 안되니까 파일을 삭제해준다.<br>
<br>
## 2.2 익스플로잇
file_get_contents로 값을 가져오고 file_put_contents로 가져온 값을 로컬에 저장하고 곧 로컬에 저장했던 파일을 삭제한다.<br>
이 말은 코드가 계속 반복되게 한다면 아마도 레이스컨디션이 가능할 것이라는 말이 된다.<br>
그런데 http:때문에 제약이 걸린다. 이 문제는 PHP 내부에서 http:까지는 wrapper로 취급하지 않는 트릭으로 인하여 LFI로 우회할 수 있다.<br>
 <br>
robots.txt를 보면 flag.php가 있는 것을 알 수 있는데 그 파일에 접근하기 위해서 http:/../../flag.php로 접근하면 될 것이다.<br>
 <br>
md5(url + 랜덤글자(a,b,c)) 니까 기존 url 값과 a,b,c중 하나를 넣어서 md5로 해싱해주고 레이스컨디션을 진행해주면 될 것이다.<br>
 <br>
http:/../../flag.php<br>
위와 같이 페이로드를 만들어주고 A라는 브라우저에서는 url 인자에 http:/../../flag.php를 넣어서 계속 반복해준다. 그리고 B라는 브라우저에서는 md5(http:/../../flag.php + 랜덤글자(a,b,c))로 해서 돌려준다.<br>
 <br>
## 2.3 결과
```
<?php
/*
If you read this,
you probably solved this challenge.
*/
// FLAG{fd17383b35a7888cd0b38595d85ca923}
[...]
}
?>
 
VM34:4 GET http://game.debu.kr/chall/904bf15a4091708872eb3740ef794c3e/img/9e7cad0030d92acc8787f3d34901cabc.jpg 404 (Not Found)
(anonymous) @ VM34:4
VM34:5 <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
[...]
</body></html>
 
VM34:4 GET
[...]
/chall/904bf15a4091708872eb3740ef794c3e/img/9e7cad0030d92acc8787f3d34901cabc.jpg was not found on this s
```
그러면 플래그를 획득할 수 있다.

Flag: FLAG{fd17383b35a7888cd0b38595d85ca923}