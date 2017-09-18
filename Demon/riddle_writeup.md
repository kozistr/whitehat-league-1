# WhiteHat League - Demon CTF

## Riddle Write-Up - 출제자 풀이

## Introduce

- Author : 김승환 (KDMHS)
- Field  : Crypto
- E-Mail : asdf7845120@gmail.com
- Data   : 2017-09-12

## Intention

- ENIGMA 에 대해 관심이 많았고 이런 암호 풀이 방법이 적어 한번 출제해 보았습니다.
- 암호화된 메시지를 올바른 키를 찾아 인증하면 됩니다.

## Solve
ENIGMA를 푸는 방법은 CRIB을 찾는 것입니다.

암호화된 메시지의 첫부분은

> YOZOF MQWBYMHBGHST AQTDVXI UMRLCRIFNQA

이러한데 이를

> START ???????????? WEATHER INFORMATION

이라고 생각할 수 있습니다.

이것을 http://www.ellsbury.com/enigmabombe.htm 이곳을 참고해 해보면
Bombe를 사용하면 되는데

```python
RFA = " " # Bombe Reflector
DA = [""]*3 # Bombe drum

SOA = [0]*20 # Scramblers relative offsets
SCA = [0]*20 # Scramblers connections

DB = [[0] *26 for row in range(26)] # Letters array
L1A = "" # Diagonal board letter 1
L2A = "" # Diagonal board letter 2

ID = "ZZZ" # Indicator drums

UT = 0 # Untraced voltages

D = [0,0,0] # Drum counter

ML = 0 # Number of menu letters
MLA =[0]*13 # Menu letters array
MC = [[0] * 13 for row in range(6)] # Menu connections array

IV = 0 # Input voltage letter
TR = 0 # Test menu letter

def Init():
	global DA,RFA,SOA,SCA,SL,IV,TR,ID,P,MLA,ML,MC
	DA = [["OUFANZJHGRCDIXMYSWBQVLPEKT","DSKLXCIHMGYVOEAWTJQZBURNPF","ZM"],["SUMKAGWIEYNZVXTRPCLJHFOQDB","EZRYIVFUHTDSCKWQXPAOBMGNJL","V"],["YQBENICPHZRTJDKASXLGVOUMFW","PCGNDYTIFMOSXEVHBKQLWUZRAJ","ZM"]]

	RFA = "FVPJIAOYEDRZXWGCTKUQSBNMHL"

	SOA[0] = "ACB"
	SOA[1] = "ACG"
	SOA[2] = "ABU"
	SOA[3] = "ACF"
	SOA[4] = "ACH"
	SOA[5] = "ACA"
	SOA[6] = "ACE"
	SOA[7] = "ACB"
	SOA[8] = "AAF"
	SOA[9] = "AAC"
	SOA[10] = "AAE"
	SOA[11] = "ACF"
	SOA[12] = "ACJ"
	SOA[13] = "ACH"

	SCA[0] = "RF"
	SCA[1] = "FT"
	SCA[2] = "TA"
	SCA[3] = "AI"
	SCA[4] = "IN"
	SCA[5] = "NM"
	SCA[6] = "MR"
	SCA[7] = "RF"
	SCA[8] = "FT"
	SCA[9] = "TO"
	SCA[10] = "OR"
	SCA[11] = "IA"
	SCA[12] = "AN"
	SCA[13] = "NI"


	SL = 14

	IV = 0 # Input letter value - A
	TR = 12 # Test register value - M

	ID = "AAA" # Indicator offset

	P = [0]*3
	P[0] = 0 # Debug printing 0 = off
	P[1] = 0 # Enigma printing 0 = off
	P[2] = 0 # Diagonal board printing 0 = off

	MLA[0] = "R"
	MLA[1] = "F"
	MLA[2] = "T"
	MLA[3] = "A"
	MLA[4] = "I"
	MLA[5] = "N"
	MLA[6] = "M"
	MLA[7] = "O"
	
	
	ML = 8 # Number of menu letters

	MC = [[1, 7, 8, 11, 0, 0 ] # "R"
		,[1, 2, 8, 9, 0, 0] # "F"
		,[2, 3, 9, 10, 0, 0] # "T"
		,[3, 4, 12, 13, 0, 0] # "A"
		,[4, 5, 12, 14, 0, 0] # "I"
		,[5, 6, 13, 14, 0, 0] # "N"
		,[6, 7, 0, 0, 0, 0] # "M"
		,[10, 11, 0, 0, 0, 0]] # "O"
def WrapScramblerOffset(SV):
	return SV % 26

def ScramblerOffset(SV,OD):
	#SV = letter, OD = drum offset, 25 = Z ring
	SV = SV + OD - 25
	return WrapScramblerOffset(SV)

def ThroughScrambler(SV,OD,CDA,T):
	#SV = letter, OD = drum offset, 25 = Z ring
	SV = ord(CDA[T][SV]) - 65 - OD + 25
	SV = WrapScramblerOffset(SV)
	if P[1] == 1:
		print chr(SV+65),
	return SV

def Scrambler(CSA,SV):
	if P[1] == 1:
		print CSA,"INPUT: " + chr(SV+65),
	for i in range(2,-1,-1):
		SV = ScramblerOffset(SV,ord(CSA[i])-65)
		SV = ThroughScrambler(SV,ord(CSA[i])-65,DA[i],0)
	SV = ord(RFA[SV]) - 65
	for i in range(0,3):
		SV = ScramblerOffset(SV,ord(CSA[i])-65)
		SV = ThroughScrambler(SV,ord(CSA[i])-65,DA[i],1)
	if P[1] == 1:
		print " OUTPUT: "+chr(SV+65)
	return SV

def PrintScrambler(): #1800
	for k in range(SL):
		print SOA[k]+":"+SCA[k],
		if k%5 == 4:
			print ""
	print ""

def SetScramblerOffset(CSA): # 2800
	CA = ""
	for i in range(3):
		L = ord(CSA[i]) + (26 - (ord(ID[i]) - 64))
		if L < 65:
			L += 26
		elif L > 90:
			L -= 26
		CA += chr(L)
	return CA

def IncScramblerOffset(CSA, D):
	CA = list(CSA)
	for i in range(3):
		CA[i] = chr(((ord(CSA[i]) - 64)%26)+65)
		if D[i] < 26:
			break
	return ''.join(i for i in CA)

def MoveDrums():
	global SOA,D
	for i in range(3):
		D[i] += 1
		if D[i] < 26:
			break
	for i in range(SL):
		if len(SOA[i]) != 0:
			SOA[i] = IncScramblerOffset(SOA[i],D)
	for i in range(3):
		D[i] %= 26

def DecIndicatorDrums():
	global ID
	IDA = list(ID)
	for i in range(3):
		IDA[i] = chr(((ord(IDA[i]) - 66)%26)+65)
		if IDA[i] != "Z":
			break
	ID = ''.join(i for i in IDA)

def SetValue(L1,L2):
	global DB,UT
	f= 0
	for i in range(ML):
		if chr(L1+65) == MLA[i]:
			f=1
			break
	if f==0:
		DB[L1][L2]=2
	else:
		DB[L1][L2]=-1
		UT +=1

def DiagonalBoard(L1,L2):
	if DB[L1][L2] ==0:
		SetValue(L1,L2)	
	if L1 != L2:
		L1,L2 = L2,L1
		if DB[L1][L2] == 0:
			SetValue(L1,L2)

def PrintDiagonalBoard():
	p = " "
	for i in range(26):
		p += chr(i+65)
	print p
	for i in range(26):
		p = chr(i+65)
		for j in range(26):
			if DB[i][j] == 0:
				p += " "
			elif DB[i][j] == 1:
				p += "|"
			elif DB[i][j] == -1:
				p += "X"
			elif DB[i][j] == 2:
				p += "O"
		print p

def ClearDiagnalBoard():
	global DB,UT
	for i in range(26):
		for j in range(26):
			DB[i][j]=0
	UT = 0

def PrintTestRegister():
	print "TEST REGISTER: "
	p = ""
	for i in range(26):
		p += chr(i+65)
	print p
	p = ""
	for i in range(26):
		if DB[TR][i] == 1:
			p += " "
		elif DB[TR][i] != 1:
			p += "|"
	print p

def TraceVoltage(i,j):
	global UT
	DB[ord(MLA[i])-65][j] = 1
	UT -= 1
	for k in range(6):
		if MC[i][k] == 0:
			return
		SV = Scrambler(SOA[MC[i][k]-1],j)
		if SCA[MC[i][k]-1][0] != MLA[i]:
			SL = ord(SCA[MC[i][k]-1][0])-65
		else:
			SL = ord(SCA[MC[i][k]-1][-1])-65
		if DB[SL][SV] != -1:
			if DB[SL][SV] != 1:
				DiagonalBoard(SL,SV)

def PrintMatch(FST):
	for i in range(len(FST)):
		print chr(FST[i][0]+65)+":"+chr(FST[i][1]+65),
		if i%5 == 4:
			print ""
	print ""

def TestStopIndicator():
	CDUP = [0]*26
	FST = []
	GS = DB[TR].index(0)
	FST.append([TR,GS])
	CDUP[TR] = GS
	CDUP[GS] = TR
	k = 0
	while len(FST) != k:
		N, V = FST[k]
		for i in range(ML):
			if SCA[i].find(chr(N+65)) != -1:
				n = ord(SCA[i][SCA[i].find(chr(N+65))-1])-65
				v = Scrambler(SOA[i],V)
				if CDUP[n] == 0 and CDUP[v] == 0:
					FST.append([n,v])
					CDUP[n] = v
					CDUP[v] = n
				else:
					if CDUP[n] == v and CDUP[v] == n:
						continue
					return False, 0
		k += 1
	global DO
	return True, FST

def Solve():
	while True:
		ClearDiagnalBoard();
		DiagonalBoard(IV,TR)
		
		MoveDrums()
		DecIndicatorDrums()
		print "INDICATOR: "+ID
		if ID == "AAA":
			break
		if P[0] == 1:
			print "SCRAMBLERS: "
			PrintScrambler()
		flag = True
		while flag:
			for i in range(ML):
				if UT == 0:
					flag = False
					break
				if P[0] == 1:
					print "CHECKING LETTER: " + MLA[i]
					print "Untraced: "+str(UT)
				if P[2] == 1:
					PrintDiagonalBoard()
				for j in range(26):
					if DB[ord(MLA[i])-65][j] == -1:
						TraceVoltage(i,j)
		VC = 0
		for i in range(26):
			if DB[TR][i] == 1:
				VC += 1
		if VC < 26:
			print "\nSTOP"
			print "INDICATOR: " + ID
			PrintTestRegister()
			flag, FST = TestStopIndicator()
			if flag == False:
				print "CONTRADICTIONS FOUNDED"
				raw_input("PRESS ENTER TO CONTINUE")
				continue
			print "PLUGBOARD: "
			PrintMatch(FST)
			raw_input("PRESS ENTER TO CONTINUE")
	print "BOMB RUN COMPLETE"

if __name__ == "__main__":
	global SOA
	print "BOMBE SETUP DATA..."
	Init()
	print "SCRAMBLERS: "
	PrintScrambler()

	print "NUMBER OF MENU LETTERS: "+str(ML)
	print "MENU LETTERS: "
	for i in range(ML):
		p = MLA[i]+":"
		for j in range(6):
			if MC[i][j] != 0:
				p += str(MC[i][j]) + " "
		print p

	print "INPUT VOLTAGE: " + chr(IV+65)
	print "INPUT STECKER LETTER: " + chr(TR+65)
	print "INDICATOR START:" + ID
	if ID != "ZZZ":
		print "OFFSETTING SCRAMBLERS"
		for k in range(SL):
			if SOA[k] != 0:
				SOA[k] = SetScramblerOffset(SOA[k])
		PrintScrambler()
	Solve()

```

이것을 사용해 돌려보면

![](https://github.com/kozistr/whitehat-league-1/blob/master/image/riddle-1.png)

이렇게 나옵니다
ITN이라 나오지만 두 번째 세 번째가 하나씩 밀려 나오므로 IUO가 맞는 ID입니다.
지금까지 얻은 정보를 사용해 보면

ID: IUO
JUMP CABLE : CM NT FP AJ
아직 Jump Cable 6개가 부족한 것으로 보입니다. 현재 있는 정보를 바탕으로 돌려보면

###1
ID: IUO
JUMP CABLE : CM NT FP AJ
> EABQT CUOEVDPIRPTL SZATHZR NNFURMATIUN

이렇게 나옵니다

SZATHZR 가 WEATHER가 나와야 하므로 SW, EZ를 알 수 있습니다.

###2
ID: IUO
JUMP CABLE : CM NT FP AJ SW EZ
> ZAAQT CUNZVDPIRPAL WEATHER NNFURMATIUN

이번에는 이렇게 나옵니다
그래서 평문으로 START를 넣으니 BUZUF이렇게 나왔고 BY, UO를 알 수 있습니다.


###3
ID: IUO
JUMP CABLE : CM NT FP AJ SW EZ BY UO
> START CONFIDPNRPAL WEATHER INFORMATION TEMORROW OS EXPECTVD TO RISE TO OROBND TEN DEKPBES TVEREFORE IT WXJ INKDRUCTED QJ ATYACI SEOUM TORIUKV TVE MELECSE OF TVE WEATVEZ TVE AIKCAL TVAN TVE NVGLE ARMV KO ATTACG IS FLAK AND TVW FLAK IS HPAYRESPECTTOALANTURZNK LND
FLAK가 FLAG

가 되어야 할거 같으므로 KG를 찾았습니다.

###4
ID: IUO
JUMP CABLE : CM NT FP AJ SW EZ BY UO KG

> START CONFIDPNTPAL WEATHER INFORMATION TEMORROW IS EXPECTED TO RISE TO AROUND TEN DEGPEES TVEREFORE IT WXJ INGTRUCTED QO ATYACI SEOUM TVRIUGV TVE RELECSE OF TVE WEATVEZ TVE SIGNAL TVAN TVE WVKLE ARMY GO ATTACK IS FLAG AND TVW FLAG IS IPAYRESPECTTOALANTURZNG END
TEMORROW가 TOMORROW

가 되어야 하지만 E는 이미 사용되어지고 있으므로

> START CONFIDPNTPAL WEATHER INFORMATION TOMORROW

이 문장을 암호화 해 보면

> YOZOF MQWBYMHBGHST AQTDVXI UMRLCRIFNQA IVENSTTD

이렇게 나오고 원래 암호화된 문장은

> YOZOF MQWBYMHBGHST AQTDVXI UMRLCRIFNQA IHENSTTD

이므로 HV임을 알 수 있습니다


최종적으로 
ID: IUO
JUMP CABLE : CM NT FP AJ SW EZ BY UO KG HV
이고 평문은
> START CONFIDENTIAL WEATHER INFORMATION TOMORROW IS EXPECTED TO RISE TO AROUND TEN DEGREES THEREFORE IT WAS INSTRUCTED TO ATTACK SEOUL THROUGH THE RELEASE OF THE WEATHER THE SIGNAL THAT THE WHOLE ARMY GO ATTACK IS FLAG AND THE FLAG IS IPAYRESPECTTOALANTURING END

Flag 는
> Demon{IPAYRESPECTTOALANTURING}
