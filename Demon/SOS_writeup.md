# WhiteHat League - Demon CTF

## SOS Write-Up - 출제자 풀이

## Introduce

- Author : 김승환 (KDMHS)
- Field  : Reversing
- E-Mail : asdf7845120@gmail.com
- Data   : 2017-09-12

## Intention

- OS 분석을 제대로 해본 분들이 적은 것 같아서 만들어 보았습니다.
- 바이너리는 암호화 되어 있고 커널 단에서 암호화가 해제 됩니다. 
- 암호 인증 루틴을 찾아 정확한 암호를 입력하면 바이너리가 실행되며 flag가 출력됩니다.

## Solve
OS를 실행시켜 cmd창을 실행시키면

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-1.png)

download를 통해 파일을 넣어줄 수 있습니다.

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-2.png)

정적 분석을 통해 해당 메시지를 탐색하면

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-3.png)

v7이 데이터의 크기인 듯 하고 데이터의 크기를 4byt로 보낸 뒤 데이터를 보내면 되는 듯 합니다.
당연히 시리얼로 보내야 하니 소스를 만들어 보내면

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-4.png)

이렇게 password를 입력하라고 나옵니다.
해당 문자열을 또 검색하면

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-5.png)

이렇게 나오며 해당 분기가 실패하면

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-6.png)

이렇게 나오게 됩니다.

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-7.png)

주요 연산 부분은 이 부분이며 해당 부분이 암호화 체크 루틴입니다.
분석을 해 보면 간단한 행렬 곱을 한다는 점을 알 수 있고

```python
import numpy as np
import numpy.linalg as lin
from ctypes import *
xy = np.array([[0x4759f2e948e8,0x3ae757a621d0,0x458d22be3808,0x22ee72b2f618],
              [0x6e079a7eac90,0x5ad1ce89f120,0x6b3d0d302630,0x35de690980b0],
              [0x82e62697e1c0,0x6c092daa34f0,0x7f91f5a75250,0x40144b21bbe0],
              [0x991390f3b2d0,0x7e5c0e31eb90,0x9534b881ee40,0x4aef433c8ad0]])
for c in range(3,-1,-1):
    cy = np.array([[69,134,129,83],[26,142,181,209],[141,166,229,225],[93,100,95,181]])
    for t in range(c):
        for i in range(4):
            tmp = cy[i][3]*(t+1)
            cy[i][3] = cy[i][0]*(t+1)
            cy[i][0] = tmp
            cy[i][1] = cy[i][1] * (t+1)
            cy[i][2] = cy[i][2] * (t+1)
    
    x = np.dot(xy,lin.inv(cy))
    for i in range(4):
        for j in range(4):
            xy[j][i] = x[i][j]
KEY = ""
for i in range(4):
    for j in range(4):
        KEY += chr(int(round(x[i][j])))
print KEY
```

이렇게 역연산 코드를 작성 할 수 있습니다.

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/SOS-8.png)

이렇게 flag가 나옵니다.