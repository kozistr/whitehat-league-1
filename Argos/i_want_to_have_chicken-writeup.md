# ARGOS : I_want_to_have_chicken, Forensic 300

### 1. 파일 확인
먼저 받은 파일 타입부터 확인 해 보았다 ㅇㅅㅇ

> zero@ubuntu:~/Desktop$ file Chicken.hwp
> Chicken.hwp: Hangul (Korean) Word Processor File 5.x

한글파일이네 하고 열어보니 흠... 별다른 내용은 없는데... 크기는 거의 2MB다.
뭔가 숨겨진거 같아서 **binwalk** 툴로 파일 내부 다른 시그니처를 검색했따

 > zero@ubuntu:~/Desktop$ binwalk -e *.hwp
 
> DECIMAL       HEXADECIMAL     DESCRIPTION
>
>2880          0xB40           GIF image data, version "89a", 177 x 250
>14336         0x3800          JPEG image data, JFIF standard 1.01
>33088         0x8140          GIF image data, version "89a", 177 x 250
>45056         0xB000          Zip archive data, encrypted at least v2.0 to extract, compressed size: 704388, uncompressed size: 708269, name: c.jpg
>749487        0xB6FAF         Zip archive data, encrypted at least v2.0 to extract, compressed size: 128912, uncompressed size: 129413, name: c1.jpg
>878435        0xD6763         Zip archive data, encrypted at least v2.0 to extract, compressed size: 197660, uncompressed size: 212548, name: c2.jpg
>1076131       0x106BA3        Zip archive data, encrypted at least v2.0 to extract, compressed size: 116720, uncompressed size: 116752, name: c3.jpg
>1192887       0x1233B7        Zip archive data, encrypted at least v2.0 to extract, compressed size: 678330, uncompressed size: 704693, name: c4.jpg
>1871253       0x1C8D95        Zip archive data, encrypted at least v2.0 to extract, compressed size: 115744, uncompressed size: 115738, name: c5.jpg
>1987033       0x1E51D9        Zip archive data, encrypted at least v2.0 to extract, compressed size: 11906, uncompressed size: 11912, name: c6.jpg
>1998975       0x1E807F        Zip archive data, encrypted at least v2.0 to extract, compressed size: 9971, uncompressed size: 9994, name: c7.jpg
>2008982       0x1EA796        Zip archive data, encrypted at least v2.0 to extract, compressed size: 22716, uncompressed size: 25421, name: c8.jpg
>2031734       0x1F0076        Zip archive data, encrypted at least v2.0 to extract, compressed size: 8177, uncompressed size: 8191, name: c9.jpg
>2040474       0x1F229A        End of Zip archive

여윽시... 2개의 **GIF** 파일과 1개의 **JPEG** 파일, 그리고 10개의 수-상한 사진이 들어있는 **쥡파일** 1개
(-e 옵션이 extract) 한번 집 파일을 열어보려 했더니... 비번이 필요하덴다;;

### 2. 압축파일 비번 풀기
흠... 비번은 어디에있지... 고민을 해 보았는데 한글파일을 잘 보면 아래부분에 이렇게 적혀있따.
> 어느 치킨집 치킨이 맛있을까?
> 치킨집 전화번호를 알아야한다!!!
> 042xxxxxxx 였던가...

이게 비번? 이란 생각에(는 설마 비번이겠어) 남은 7자리를 숫자 범위 내에서 __advanced zip password recovery__ 툴로 __brute-force__ 했다.
그랬더리 레알루 크랙이 되긴 했다;;
>Advanced ZIP Password Recovery statistics:
>ncrypted ZIP-file: C:\Users\zero\Dropbox\CTFs\asdfff.zip
>Total passwords: 8,248,861
>Total time: 357ms 
>Average speed (passwords per second): 23,106,053
>Password for this file: 0428248867
>Password in HEX: 30 34 32 38 32 34 38 38 36 37

***0428248867*** 뙇! 오졌따리...
~~(사실 치킨집이라길래 042로 시작하길래 대전에 있는 치킨집 번호 다 따서 넣어본건 안비밀 ㅎㅎ;;..)~~

### 3. 두둥... 압축이 풀렸더니...
이미지가 10개가 정상적으로 나왔는디 문제는 플레그 관련 이미지가 없었다.. 흠...

>zero@ubuntu:~/Desktop/sec$ ls
>c1.jpg  c2.jpg  c3.jpg  c4.jpg  c5.jpg  c6.jpg  c7.jpg  c8.jpg  c9.jpg  c.jpg

흠... 하면서 파일 하나하나 **binwalk** 툴을 사용해서 파일 하나에 여러 파일이 들어가 있는지
시그니처 좀 봐 주고 **binwalk, foremost** 툴로 추출추출해주고 안되면 __손-카빙__

그래서 발견한건 **c.jpg** 파일에서 의심장한 이미지인 ~~콩~~홍진호 사진이 9개나 박힌 사진을 찾았따.

 > zero@ubuntu:~/Desktop$ binwalk -e *.hwp
 > 
> DECIMAL       HEXADECIMAL     DESCRIPTION
>
>0             0x0             JPEG image data, JFIF standard 1.01
>389184        0x5F040         JPEG image data, JFIF standard 1.01

>zero@ubuntu:~/Desktop/sec
>zero@ubuntu:~/Desktop/sec foremost c.jpg
>Processing: c.jpg
>|*|
>zero@ubuntu:~/Desktop/sec
>zero@ubuntu:~/Desktop/sec/output/jpg ls
>00000000.jpg  00000760.jpg   <---- 요놈이 그 의문의 사진

### 4. 흠... 이제 뭘 해보지...
사실 위 3번 까지 푸는데 1~2시간 정도 걸렸다. 근데 이제 뭘 더 해야지..?
#### 4-1. 문자열 찾자
먼저 문자열을 다 뒤져 봤다...
>zero@ubuntu:~/Desktop/sec strings * | grep ARGOS

실패!...
#### 4-2. 이미지 정보 뒤져보자
사진 속성이나 툴을 사용해서 **exif inforamtion** 을 다 봐봐도 소득 읎..

#### 4-3. 사진 늘려보자
사진을 보면 아래 흰색 바가 조금 보이는데 혹시 이미지 크기가 줄어들어 잘린 이미지가 있을까 해서
이미지 크기를 늘려 아래부분을 확장 해 봤는데... 실패..

#### 4-4. 혹시 steganography? 
그래서 얼른 __java__ 하고 __openstego__ 를 받기 시작했다. 다른 툴들도 찾아서 해 보았다...
사용되는 비밀번호는 모르니 없음으로도 해 보고 넣어보기도 해 봤는데도 잘 안됬다...


### 5. 그렇게 대회 끗...
실화다...

### 6. 집와서 다시 풀어봄
~~무박3일에 지쳐 한숨땡기고와서~~다시 풀어보려니 머리 속에 __steghide__ 라는 툴이 생각났다..
[steghide](https://futureboy.us/stegano/decinput.html) 해봤더니 또 다른 이미지가 나왔다.
이번엔 **~~콩~~진호**가 아닌 **원빈** 이 '아직 1발 남았다' ... 막 이러는겨..
?? 한번 똑같이 더 돌려 봤더니 플레그가...
> flag is ARGOS{cH1ckEn_ls_4_g0D}

흠... 
