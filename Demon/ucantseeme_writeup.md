# WhiteHat League - Demon CTF

## ucantseeme Write-Up - 출제자 풀이

## Introduce

- Author : 박서빈 (moonoik)
- Field  : Reversing
- E-Mail : eatf822@gmail.com
- Data   : 2017-08-31

## Intention

- flag값을 base32로 암호화한 뒤 enc.bin 파일로 저장하여 난독화 된 바이너리를 분석 한 뒤
- enc.bin 에서 flag 값을 복호화
- enc.bin파일에서 flag값을 복호화 한뒤 인증 플래그 형식은 Demon{…}

## Encryption
주어진 바이너리로 쉘에서 인자를 주면 그값을 암호화 하여 enc.bin으로 저장을 하게 된다.

암호화 할 때 쓰인 코드는 아래와 같다.

```c
static const char base32_alphabet[32] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'B', 'C', 'D', 'F', 'G', 'H',
        'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R',
        'S', 'T', 'V', 'W', 'X', 'Y', 'Z', '?'
};

int base32_encode(char *dst, size_t size, const void *data, size_t len)
{
        size_t i = 0;
        const uint8_t *p = data;
        const char *end = &dst[size];
        char *q = dst;

        do {
                size_t j, k;
                uint8_t x[5];
                char s[8];

                switch (len - i) {
                case 4:
                        k = 7;
                        break;
                case 3:
                        k = 5;
                        break;
                case 2:
                        k = 3;
                        break;
                case 1:
                        k = 2;
                        break;
                default:
                        k = 8;
                }

                for (j = 0; j < 5; j++)
                        x[j] = i < len ? p[i++] : 0;

        s[0] = (x[0] & 0x1F);
        s[1] = ((x[0] & 0xE0) >> 5) | ((x[1] & 0x03) << 3);
        s[2] = (x[1] & 0x7C) >> 2;
        s[3] = ((x[1] & 0x80) >> 7) | ((x[2] & 0x0F) << 1);
        s[4] = ((x[2] & 0xF0) >> 4) | ((x[3] & 0x01) << 4);
        s[5] = ((x[3] & 0x3E) >> 1);
		s[6] = ((x[3] & 0xC0) >> 6) | ((x[4] & 0x07) << 2);
        s[7] = (x[4] & 0xF8) >> 3;

                for (j = 0; j < k && q != end; j++) {
                        *q++ = base32_alphabet[(uint8_t) s[j]];
                }

                if (end == q) {
                        break;
                }

        } while (i < len);

        return q - dst;
}
```

## Script
Base32를 기반으로 만든 암호화 코드이기 때문에 복호화 역시 가능하며 이때 코드는 아래와 같다.	

```c
int	
base32_decode(char *dst, size_t size, const void *data, size_t len)
{
        const char *end = &dst[size];
        const unsigned char *p = data;
        char s[8];
        char *q = dst;
        int pad = 0;
        size_t i, si;

        if (0 == base32_map[0]) {
                for (i = 0; i < G_N_ELEMENTS(base32_map); i++) {
                        const char *x;

                        x = memchr(base32_alphabet, toupper(i),
                                           sizeof base32_alphabet);
                        base32_map[i] = x ? (x - base32_alphabet) : (unsigned char) -1;
                }
        }

        memset(&s[0], 0, sizeof s);
        si = 0;
        i = 0;

        while (i < len) {
                unsigned char c;

                c = p[i++];
                if ('=' == c) {
                        pad++;
                        c = 0;
                } else {
                        c = base32_map[c];
                        if ((unsigned char) -1 == c) {
                                return -1;
                        }
                }

                s[si++] = c;

                if (G_N_ELEMENTS(s) == si || pad > 0 || i == len) {
                        char b[5];
                        size_t bi;

                        memset(&s[si], 0, G_N_ELEMENTS(s) - si);
                        si = 0;
            b[0] =
                (s[0] & 0x1F) |
                ((s[1] & 0x07) << 5);
            b[1] =
                ((s[1] & 0x18) >> 3) |
                ((s[2] & 0x1F) << 2) |
                ((s[3] & 0x01) << 7);
b[2] =
                ((s[3] & 0x1E) >> 1) |
                ((s[4] & 0x0F) << 4);
            b[3] =
                ((s[4] & 0x10) >> 4) |
                ((s[5] & 0x1F) << 1) |
                ((s[6] & 0x03) << 6);
            b[4] =
                ((s[6] & 0x1C) >> 2) |
                ((s[7] & 0x1F) << 3);


                        for (bi = 0; bi < G_N_ELEMENTS(b) && q != end; bi++) {
                                *q++ = b[bi];
                        }
                }

                if (end == q) {
                        break;
                }
        }

        return q - dst;
}
```

Base32암호화를 해준 뒤 글자당 4비트씩 스왑하기 때문에

base32 디코딩을 하기전에 4비트씩 스왑까지 해주어야 flag를 획득할 수 있다.

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/ucantseeme-1.png)

제공되는 enc.bin을 보면 위와 같은 값이 들어가 있으며 복호화를 하면 flag를 획득할 수 있다.

Flag: Demon{Security...Security_never_safe.}
