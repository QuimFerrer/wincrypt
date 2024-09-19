*-09ago2021
*-Leer certificado digital SAT MEXICO(.cer)
*-Autor de los códigos: Fernando Mora
*-Adaptado por zarlu@hotmail.com
*-Se requiere openssl.exe en el directorio de ejecución
*-Proceso: A partir del archivo .cer se convierte a .pem con openssl
*-y de ahí se toma la información.
*-Link fuente:
*-https://groups.google.com/g/publicesvfoxpro/c/7KV_cEaxq_Y/m/FtJtmRGSBQAJ
*-leercersat(cFileCer,cModiFile)
*-cFileCer=certificado archivo .cer
*-cModiFile=visualizar archivo .txt generado. Valor lógico (.t./.f.)

PARAMETERS lcCer,lcModi

CLEAR
=leercersat(lcCer,lcModi)

FUNCTION leercersat(cFileCer,cModiFile)
	IF EMPTY(cFileCer) .or. LOWER(JUSTEXT(cFileCer))<>"cer"
		RETURN
	ENDIF
	SET SAFETY OFF
	SET DATE TO French
	SET CENTURY On
	=SetDeclarationsAPI()
	cFileCer=["]+cFileCer+["]
	lcCer=cFileCer
	lcPem=FORCEeXT(JUSTstem(lcCer),"pem")
	lcEjecutar = "OpenSSL" + " x509 -inform DER -in "+lcCer+" -out "+lcPem
	loShell = CREATEOBJECT("WScript.Shell")
	lcArchivo = "crearpem.bat"
	StrToFile(lcEjecutar, lcArchivo)
	loShell.Run(lcArchivo, 0, 3) 
	DELETE FILE (lcArchivo)&&elimina bat
	RELEASE loShell
	oFSO=CreateObject('Scripting.FileSystemObject')&&verificar si existe archivo
	If !oFSO.FileExists(lcPem)
		MESSAGEBOX("No se pudo crear el archivo PEM",48,"Verifique")
		RETURN
	EndIf	
	lnCertContext=GetImportCerCrtPemDer(lcPem)&&contexto al pem
	GetDecodeCertificateX509(lnCertContext)&&decodificar pem
	DELETE FILE *.pem&&elimina el PEM
	IF cModiFile=.t.
		MODIFY FILE ADDBS(FULLPATH(""))+"CertX509Decode.txt"
	EndIF
*!*		#define CRLF CHR(13)+CHR(10)
*!*		lcLeer=FILETOSTR("CertX509Decode.txt")
*!*		lcEmisor=ALLTRIM(STREXTRACT(STREXTR(lcLeer, [Emisor],[Fecha Emision]),[CN=],CRLF))
*!*		lcSujeto=ALLTRIM(STREXTRACT(STREXTR(lcLeer, [Sujeto],[Algoritmo]),[CN=],CRLF)) 
*!*		lcRFC=ALLTRIM(STREXTRACT(STREXTR(lcLeer, [Sujeto],[Algoritmo]),[OID.2.5.4.45=],[;]))
*!*		?lcEmisor
*!*		?lcSujeto
*!*		?lcRfc
ENDFUNC

*------------ Constantes CryptStringToBinary, para: dwFlags 
#DEFINE CRYPT_STRING_BASE64HEADER				0x00000000
#DEFINE CRYPT_STRING_BASE64 					0x00000001
#DEFINE CRYPT_STRING_BINARY					0x00000002
#DEFINE CRYPT_STRING_BASE64REQUESTHEADER			0x00000003
#DEFINE CRYPT_STRING_HEX					0x00000004
#DEFINE CRYPT_STRING_HEXASCII					0x00000005
#DEFINE CRYPT_STRING_BASE64_ANY					0x00000006
#DEFINE CRYPT_STRING_ANY					0x00000007
#DEFINE CRYPT_STRING_HEX_ANY					0x00000008
#DEFINE CRYPT_STRING_BASE64X509CRLHEADER			0x00000009
#DEFINE CRYPT_STRING_HEXADDR					0x0000000a
#DEFINE CRYPT_STRING_HEXASCIIADDR				0x0000000b
#DEFINE CRYPT_STRING_HEXRAW					0x0000000c
#DEFINE CRYPT_STRING_STRICT					0x20000000
*------ Constantes CertOpenStore para:
#DEFINE PKCS_7_ASN_ENCODING					65536
#DEFINE X509_ASN_ENCODING					1
*---------------------------------------------------------------------

*---PROCEDURES-----
PROCEDURE GetImportCerCrtPemDer()
	PARAMETERS tcFilePemOrCer AS String
	pCertContext = 0
	cStringCert=FILETOSTR(tcFilePemOrCer)
	IF !EMPTY(cStringCert)
		*----- Decodificamos la cadena para ASN1
		pbCertEncoded = GetCryptStringToBinary(cStringCert)
		IF !EMPTY(pbCertEncoded)
			dwCertEncodingType = BITOR(PKCS_7_ASN_ENCODING, X509_ASN_ENCODING)
			cbCertEncoded = LEN(pbCertEncoded)
			pCertContext = CertCreateCertificateContext(dwCertEncodingType, pbCertEncoded, cbCertEncoded)
		ELSE
			MESSAGEBOX("No se pudo decodificar el archivo", 16, _SCREEN.Caption)
		ENDIF		
	ELSE
		MESSAGEBOX("El archivo esta vacio", 16, _SCREEN.Caption)
	ENDIF
	RETURN pCertContext
ENDPROC

PROCEDURE GetCryptStringToBinary()
	PARAMETERS tcStrToDecode AS String
	*------- Convertimos binarios a Asn1
	pszString = tcStrToDecode
	cchString = LEN(pszString)
	pbBinary=""
	dwBufferLen=0
	pdwSkip=0
	pdwFlags=0
	nResp = CryptStringToBinary(pszString, cchString, CRYPT_STRING_ANY, NULL, @dwBufferLen, @pdwSkip, @pdwFlags)
	pbBinary = SPACE(dwBufferLen)
	DO CASE
	CASE pdwFlags=0
		*------- Base64, with certificate beginning and ending headers.
		CryptStringToBinary(pszString, cchString, CRYPT_STRING_BASE64HEADER, @pbBinary, @dwBufferLen, @pdwSkip, @pdwFlags)
	CASE pdwFlags=1
		*------- Base64, without headers.
		CryptStringToBinary(pszString, cchString, CRYPT_STRING_BASE64, @pbBinary, @dwBufferLen, @pdwSkip, @pdwFlags)
	CASE pdwFlags=2
		*------- Pure binary copy.
		pbCertEncoded=tcStrToDecode
	ENDCASE
	RETURN pbBinary
ENDPROC

PROCEDURE GetDecodeCertificateX509()
	LPARAMETERS tpCertContext AS Long
	cCertInfo = GetStructure_CertInfo(tpCertContext)
	cVersion = GetVersion(cCertInfo)
	cSerialNumber = STRCONV(GetSerialNumber(cCertInfo),15)
	cSignatureAlg = GetSignatureAlgorithm(cCertInfo)
	cIssuer = GetIssuer(tpCertContext)
	tNotBefor = GetNotBefore(tpCertContext)
	tNotAfter = GetNotAfter(tpCertContext)
	cSubject = GetSubject(tpCertContext)
	cPublicKeyInfo = GetSubjectPublicKeyInfo(cCertInfo)
	bPublicKeyValue = GetSubjectPublicKeyValue(cCertInfo)
	cPublicKeyValue = STRCONV(bPublicKeyValue,15)
	cExponent = GetExponent(bPublicKeyValue)
	cModulos = STRCONV(GetModulus(bPublicKeyValue, SUBSTR(cPublicKeyInfo, 1, AT(";", cPublicKeyInfo)-1)),13)
	cCertificateType = GetCertificateType(tpCertContext)
	cCertificateEncoded = STRCONV(GetCertificateEncoded(tpCertContext),13)
	*------ Salida a Texto
TEXT TO lcFileText TEXTMERGE NOSHOW ADDITIVE 
Versión: <<cVersion>>
Número de serie: <<cSerialNumber>>
Algoritmo de Firma: <<cSignatureAlg>>
Emisor : <<cIssuer>>
Fecha Emision: <<tNotBefor>>
Fecha Caduca: <<tNotAfter>>
Sujeto : <<cSubject>>
Algoritmo de Clave Publica: <<cPublicKeyInfo>>
Clave Pública: <<cPublicKeyValue>>
Exponente: <<cExponent>>
Modulus: <<cModulos>>
Tipo de Certificado: <<cCertificateType>>
Certificado Codificado: <<cCertificateEncoded>>
ENDTEXT
	*------ Grabamos en archivo de texto
	STRTOFILE(lcFileText, ADDBS(FULLPATH(""))+"CertX509Decode.txt")
	*MODIFY FILE ADDBS(FULLPATH(""))+"CertX509Decode.txt"
ENDPROC

*----procedures para información por dato del certificado
PROCEDURE GetStructure_CertInfo()
	LPARAMETERS tpCertContext AS Long
	lbCertInfo	= SYS(2600, tpCertContext, 20)
	lpCertInfo 	= CTOBIN(SUBSTR(lbCertInfo, 13, 4), "4RS")
	lcCertInfo	= SYS(2600, lpCertInfo, 112)
	RETURN lcCertInfo
ENDPROC

PROCEDURE GetVersion()
	LPARAMETERS tcCertInfo AS String
	lpVersion1	= CTOBIN(SUBSTR(tcCertInfo,1,4),"4RS")
	RETURN lpVersion1 + 1
ENDPROC

PROCEDURE GetSerialNumber()
	LPARAMETERS tcCertInfo AS String
	lbSerialNumber = SUBSTR(tcCertInfo, 5, 8)
	lnSerialNumber = CTOBIN(SUBSTR(lbSerialNumber, 1, 4),"4RS")
	lpSerialNumber = CTOBIN(SUBSTR(lbSerialNumber, 5, 4),"4RS")
	lcSerialNumber = SYS(2600, lpSerialNumber, lnSerialNumber)
	lcSerialRevers = GetReverseString(lcSerialNumber)
	RETURN lcSerialRevers
ENDPROC

PROCEDURE GetSignatureAlgorithm()
	LPARAMETERS tcCertInfo AS String
	lbSignAlgorithm	= SUBSTR(tcCertInfo, 13, 12)
	lpAlgorithmOID	= CTOBIN(SUBSTR(lbSignAlgorithm, 1, 4),"4RS")
	lnAlgorithmPara	= CTOBIN(SUBSTR(lbSignAlgorithm, 5, 4),"4RS")
	lpAlgorithmPara = CTOBIN(SUBSTR(lbSignAlgorithm, 9, 4),"4RS")
	lcAlgorithmOID	= SYS(2600, lpAlgorithmOID, GetStrLenA(lpAlgorithmOID))
	lcAlgorithmPara	= STRCONV(SYS(2600, lpAlgorithmPara, lnAlgorithmPara),15)
	RETURN lcAlgorithmOID +"; " + lcAlgorithmPara
ENDPROC

PROCEDURE GetIssuer()
	LPARAMETERS tpCertContext AS Long
	lcIssuer = ""
	lpCertInfo  = CTOBIN(SYS(2600, tpCertContext + 12, 4), "4RS")
	IF lpCertInfo > 0
		lcIssuer = GetCertNameToString(lpCertInfo + 24)
	ENDIF
	RETURN lcIssuer
ENDPROC

PROCEDURE GetNotBefore()
	LPARAMETERS tpCertContext AS Long
	ltNotBefore = CTOT("")
	lpCertInfo  = CTOBIN(SYS(2600, tpCertContext+ 12, 4), "4RS")
	IF lpCertInfo > 0
		lpNotBefore  = lpCertInfo + 32
		lpSystemTime = SPACE(16)
		IF FileTimeToSystemTime(lpNotBefore, @lpSystemTime)#0 
			ltNotBefore = GetBinatyToDateTime(lpSystemTime)
		ENDIF
	ENDIF
	RETURN ltNotBefore
ENDPROC

PROCEDURE GetNotAfter()
	LPARAMETERS tpCertContext AS Long
	ltNotAfter = CTOT("")
	lpCertInfo = CTOBIN(SYS(2600, tpCertContext + 12, 4), "4RS")
	IF lpCertInfo > 0
		lpNotAfter = lpCertInfo + 40
		lpSystemTime = SPACE(16)
		IF FileTimeToSystemTime(lpNotAfter, @lpSystemTime)#0
			ltNotAfter = GetBinatyToDateTime(lpSystemTime)
		ENDIF
	ENDIF	
	RETURN ltNotAfter 
ENDPROC

PROCEDURE GetSubject()
	LPARAMETERS tpCertContext AS Long
	lcSubjectStr = ""
	IF tpCertContext>0
		lpCertInfo = CTOBIN(SYS(2600, tpCertContext + 12, 4), "4RS")
		IF lpCertInfo > 0
			lcSubjectStr=GetCertNameToString(lpCertInfo + 48)
		ENDIF
	ENDIF
	RETURN lcSubjectStr
ENDPROC

PROCEDURE GetSubjectPublicKeyInfo()
	LPARAMETERS tcCertInfo AS String
	lbSubjectPubKey = SUBSTR(tcCertInfo,57,12)
	lpAlgorithmPKey = CTOBIN(SUBSTR(lbSubjectPubKey, 1, 4),"4RS")
	lnAlgorithmPara = CTOBIN(SUBSTR(lbSubjectPubKey, 5, 4),"4RS")
	lpAlgorithmPara = CTOBIN(SUBSTR(lbSubjectPubKey, 9, 4),"4RS")	
	lcAlgorithmPKey = SYS(2600, lpAlgorithmPKey, GetStrLenA(lpAlgorithmPKey))
	lcAlgorithmPara = STRCONV(SYS(2600, lpAlgorithmPara, lnAlgorithmPara),15)	
	RETURN lcAlgorithmPKey +"; "+ lcAlgorithmPara
ENDPROC

PROCEDURE GetSubjectPublicKeyValue()
	LPARAMETERS tcCertInfo AS String
	lbPublicKey	= SUBSTR(tcCertInfo,69,8)
	lnPublicKey = CTOBIN(SUBSTR(lbPublicKey, 1, 4),"4RS")
	lpPublicKey = CTOBIN(SUBSTR(lbPublicKey, 5, 4),"4RS")
	lcPublicKey = SYS(2600, lpPublicKey, lnPublicKey)
	RETURN lcPublicKey
ENDPROC

PROCEDURE GetExponent()
	LPARAMETERS tbPublicKey AS String
	cAsn1Exponent = RIGHT(tbPublicKey,3)
	cB64Exponent = STRCONV(cAsn1Exponent,13)
	RETURN cB64Exponent
ENDPROC

PROCEDURE GetModulus()
	PARAMETERS tbPublicKey AS String, tcIdAlgorithm AS String
	nLenPubK=LEN(tbPublicKey)
	IF VARTYPE(tcIdAlgorithm)<>"C"
		tcIdAlgorithm="1.2.840.113549.1.1.5"
	ENDIF
	cAsn1Modulus=tbPublicKey
	DO CASE
	CASE LEFT(tcIdAlgorithm,13)<>"1.2.840.10045" AND LEFT(tcIdAlgorithm,9)<>"1.3.132.0"
		*----- Algorithm RSA Cryptography (Rivest, Shamir y Adleman)
		nIniChr=AT(CHR(0),tbPublicKey)+1
		nEndChr=AT(STRCONV("0203010001",16), tbPublicKey)
		IF nEndChr==0
			nEndChr=AT(STRCONV("020103",16), tbPublicKey)
		ENDIF
		IF nIniChr>nEndChr
			bIni512=STRCONV("30470240",16)
			nIniChr=AT(bIni512,tbPublicKey)+LEN(bIni512)
		ENDIF
		cAsn1Modulus=SUBSTR(tbPublicKey, nIniChr, nEndChr-nIniChr)
	CASE LEFT(tcIdAlgorithm,13)=="1.2.840.10045" OR LEFT(tcIdAlgorithm,9)=="1.3.132.0"
		*----- Algorithm ECC Cryptography (Elliptic Curve Cryptography)
		cAsn1Modulus=tbPublicKey
	ENDCASE
	RETURN cAsn1Modulus
ENDPROC

PROCEDURE GetCertificateType()
	LPARAMETERS tpCertContext AS Long
	lcCertType = ""
	IF tpCertContext>0
		lcCertContext = SYS(2600, tpCertContext, 20)
		lnCertType = CTOBIN(SUBSTR(lcCertContext, 1, 4), "4RS")
		lcCertType = IIF(lnCertType=1, "X509Certificate", "PKCS7Certificate")
	ENDIF
	RETURN lcCertType
ENDPROC

PROCEDURE GetCertificateEncoded()
	LPARAMETERS tpCertContext AS Long
	lbCertEncoded = ""
	IF tpCertContext>0
		lcCertContext = SYS(2600, tpCertContext, 20)
		lpCertEncoded = CTOBIN(SUBSTR(lcCertContext, 5, 4), "4RS")
		lnCertEncoded = CTOBIN(SUBSTR(lcCertContext, 9, 4), "4RS")
		lbCertEncoded = SYS(2600, lpCertEncoded, lnCertEncoded)
	ENDIF
	RETURN lbCertEncoded
ENDPROC

PROCEDURE GetReverseString()
	LPARAMETERS tcStringToReverse AS String 
	LOCAL lcReverse, nRev
	lcReverse=""
	FOR nRev = LEN(tcStringToReverse) TO 1 STEP -1
		lcReverse = lcReverse + SUBSTR(tcStringToReverse, nRev,1)
	NEXT
	RETURN lcReverse
ENDPROC

PROCEDURE GetCertNameToString()
	LPARAMETERS pbCertNameBlob AS Long
	*----- Valores posibles para wDwStrType, pueden ser la suma de varios
	SIMPLENAMESTR     = 1
	OIDNAMESTR	  = 2
	X500NAMESTR	  = 3
	SEMICOLONFLAG     = 0x40000000
	CRLFFLAG	  = 0x08000000
	NOPLUSFLAG	  = 0x20000000
	NOQUOTINGFLAG     = 0x10000000
	NAMEREVERSE	  = 0x02000000
	DISABLEIE4UTF8    = 0x00010000
	ENABLEPUNYCODE    = 0x00200000
	*----- Asignamos valores a Parametros
	nCertEncodTyp = BITOR(PKCS_7_ASN_ENCODING, X509_ASN_ENCODING)
	cpName 		  = pbCertNameBlob
	nDwStrType 	  = BITOR(X500NAMESTR, OIDNAMESTR, NAMEREVERSE, SEMICOLONFLAG)
	lcNameDecoded = ""
	lnNameLong    = 0
	*----- Intento 1, obtenemos longitud de cadena
	lnNameLong = CertNameToStr(nCertEncodTyp, cpName, nDwStrType, @lcNameDecoded, @lnNameLong)
	IF lnNameLong <> 0
		*----- Intento 2, conociendo longitud de cadena, Obtenemos el nombre decodificado
		lcNameDecoded= REPLICATE(CHR(0), lnNameLong)
		CertNameToStr(nCertEncodTyp, cpName, nDwStrType, @lcNameDecoded, @lnNameLong)
	ENDIF
	*----- La función devuelve una cadena terminada en nulo, quitamos el CHR(0) que represanta nulo
	RETURN STRTRAN(lcNameDecoded, CHR(0), "")
ENDPROC

PROCEDURE GetBinatyToDateTime()
	LPARAMETERS tbSystemTime AS String
	ltDateTime = ""
	IF !EMPTY(tbSystemTime)
		wYear	= CTOBIN(SUBSTR(tbSystemTime,1,2),"2RS")
		wMonth	= CTOBIN(SUBSTR(tbSystemTime,3,2),"2RS")
		wDayWeek = CTOBIN(SUBSTR(tbSystemTime,5,2),"2RS")
		wDay 	= CTOBIN(SUBSTR(tbSystemTime,7,2),"2RS")
		wHour 	= CTOBIN(SUBSTR(tbSystemTime,9,2),"2RS")
		wMinute  = CTOBIN(SUBSTR(tbSystemTime,11,2),"2RS")
		wSecond  = CTOBIN(SUBSTR(tbSystemTime,13,2),"2RS")
		wMilSec  = CTOBIN(SUBSTR(tbSystemTime,15,2),"2RS")
		ltDateTime = DATETIME(wYear, wMonth, wDay, wHour, wMinute, wSecond)
	ENDIF
	RETURN ltDateTime
ENDPROC

*----apis
PROCEDURE SetDeclarationsAPI()
	DECLARE LONG CertCreateCertificateContext IN Crypt32;
		LONG	dwCertEncodingType,;
		STRING	pbCertEncoded,;
		LONG	cbCertEncoded

	DECLARE LONG CryptStringToBinary IN Crypt32;
		STRING 	@pszString, ;
		LONG 	cchString, ;
		LONG 	dwFlags,;
		STRING 	@pbBinary, ;
		LONG 	@pcbBinary,;
		LONG 	@pdwSkip, ;
		LONG 	@pdwFlags

	DECLARE LONG CertNameToStr IN Crypt32;
		LONG	dwCertEncodingType, ;
		LONG	pName, ;
		LONG	dwStrType, ;
		STRING	@psz, ;
		LONG	csz

	*------ Kernel32
	DECLARE LONG FileTimeToSystemTime IN Kernel32;
		LONG 	lpFileTime,;
		STRING	@lpSystemTime

	*------ Determina la longitud de un puntero, no devuelve en caracter null de finalización
	DECLARE LONG lstrlenA IN Kernel32 AS GetStrLenA;
		LONG	lpString
ENDPROC
