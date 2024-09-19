CLEAR
CLOSE DATABASES

* 1. Valido el archivo p12
DECLARE LONG PFXIsPFXBlob IN Crypt32 STRING pPFX
DECLARE LONG GetProcessHeap IN Kernel32
DECLARE LONG GetProcessHeap IN Kernel32

DECLARE LONG HeapAlloc IN Kernel32;
	LONG 	hHeap,;
	LONG 	dwFlags,;
	LONG 	dwBytes

DECLARE LONG HeapFree IN Kernel32;
	LONG 	hHeap,;
	LONG 	dwFlags,;
	LONG 	lpMem
DECLARE RtlMoveMemory IN Kernel32;
	LONG	Destination,;
	STRING @Source,;
	LONG	Length
	
* 2. Verifico la clave del archivo p12
DECLARE INTEGER PFXVerifyPassword IN Crypt32;
 	STRING 	pfx,;
	STRING  szPassword,;
	LONG 	dwFlags

*3. Importa los certificados
#DEFINE CRYPT_EXPORTABLE						0x00000001
#DEFINE CERT_STORE_PROV_SYSTEM					10
#DEFINE CERT_SYSTEM_STORE_CURRENT_USER			0x00010000
#DEFINE PKCS_7_ASN_ENCODING						0x00010000  
#DEFINE X509_ASN_ENCODING 						0x00000001
#DEFINE CERT_FIND_SUBJECT_STR             		0x00080007

DECLARE LONG PFXImportCertStore IN Crypt32;
 	STRING  @pfx,;
	STRING  szPassword,;
	LONG dwFlags

DECLARE LONG CertOpenStore IN Crypt32;
	LONG 	 lpszStoreProvider,;
	LONG 	 dwEncodingType,;
	LONG 	 hCryptProv,;
	LONG 	 dwFlags,;
	STRING 	 pvPara
	
*4. Busco el nombre del dueño del certificado
DECLARE INTEGER CertFindCertificateInStore IN Crypt32;
	INTEGER hCertStore,;
	LONG dwCertEncodingType,;
	LONG dwFindFlags,;
	LONG dwFindType,;
	STRING @pvFindPara,;
	INTEGER pPrevCertContext  

DECLARE LONG CertCloseStore IN crypt32;
	LONG	 hCertStore,;
	LONG	 dwFlags

DECLARE LONG lstrlenA IN Kernel32 AS GetStrLenA;
		LONG	lpString

DECLARE LONG CertNameToStr IN Crypt32;
	LONG	dwCertEncodingType, ;
	LONG	pName, ;
	LONG	dwStrType, ;
	STRING	@psz, ;
	LONG	csz

DECLARE LONG FileTimeToSystemTime IN Kernel32;
	LONG 	lpFileTime,;
	STRING	@lpSystemTime

*5 Trabajar con el certificado
#DEFINE CRYPT_STRING_BASE64HEADER	0x00000000

DECLARE LONG CryptBinaryToString IN Crypt32;
		STRING 	 pbBinary, ;
		LONG 	 cbBinary, ;
		LONG 	 dwFlags,;
		STRING 	@pszString, ;
		LONG	@pcchString

DECLARE LONG BCryptOpenAlgorithmProvider IN BCrypt; 
	LONG 	@phAlgorithm,;
	STRING 	 pszAlgId,; 
	STRING 	 pszImplementation,;
	LONG 	 dwFlags

DECLARE LONG BCryptGetProperty IN BCrypt;
	LONG 	hObject,;
	STRING 	pszProperty,;
	LONG 	@pbOutput,;
	LONG 	cbOutput,;
	LONG 	@pcbResult,;
	LONG 	dwFlags
	
DECLARE LONG BCryptCreateHash IN BCrypt; 
	LONG 	hAlgorithm,;
	LONG 	@phHash,;
	STRING 	@pbHashObject,;
	LONG 	cbHashObject,;
	STRING 	pbSecret,;
	LONG 	cbSecret,; 
	LONG 	dwFlags
	
DECLARE LONG BCryptHashData IN BCrypt; 
	LONG 	hHash,;
	STRING 	pbInput,;
	LONG 	cbInput,;
	LONG 	dwFlags 

DECLARE LONG BCryptFinishHash IN BCrypt; 
	LONG 	hHash,;
	STRING 	@pbOutput,;
	LONG 	cbOutput,;
	LONG 	dwFlags 

DECLARE LONG BCryptCloseAlgorithmProvider IN BCrypt; 
	LONG 	hAlgorithm,;
	LONG 	dwFlags	

DECLARE LONG BCryptDestroyHash IN BCrypt; 
	LONG 	hHash 

* 6 Usar el certificado para firmar
#DEFINE CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG		0x00010000
#DEFINE PRIVATEKEYBLOB 							0x7
#DEFINE BCRYPT_RSA_ALGORITHM 					STRCONV("RSA" + CHR(0), 5)
#DEFINE BCRYPT_SHA1_ALGORITHM 					STRCONV("SHA1" + CHR(0), 5)
#DEFINE LEGACY_RSAPRIVATE_BLOB					STRCONV("CAPIPRIVATEBLOB" + CHR(0), 5)

DECLARE LONG BCryptImportKeyPair IN BCrypt; 
	LONG 	 hAlgorithm,;
	LONG 	 hImportKey,;
	STRING 	 pszBlobType,;
	LONG 	@phKey,;
	STRING 	 pbInput,;
	LONG 	 cbInput,; 
	LONG 	 dwFlags 

DECLARE LONG BCryptSignHash IN BCrypt;  
	LONG 	 hKey,;
	LONG 	@pPaddingInfo,;
	STRING 	 pbInput,;  
	LONG 	 cbInput,;
	STRING 	@pbOutput,;
	LONG 	 cbOutput,;  
	LONG 	@pcbResult,;
	LONG 	 dwFlags
	
DECLARE LONG BCryptDestroyKey IN BCrypt; 
	LONG 	hKey
	
DECLARE LONG CryptAcquireCertificatePrivateKey IN crypt32;
	LONG	 pCert,;
	LONG	 dwFlags,;
	LONG	 pvParameters,;
	LONG	@phCryptProvOrNCryptKey,;
	LONG	@pdwKeySpec,;
	LONG	@pfCallerFreeProvOrNCryptKey

DECLARE LONG CryptGetUserKey IN Advapi32;
	LONG 	 hProv,;
	LONG 	 dwKeySpec,;
	LONG 	@phUserKey

DECLARE LONG CryptExportKey IN Advapi32;
	LONG 	 hKey,;
	LONG 	 hExpKey,;
	LONG 	 dwBlobType,;
	LONG 	 dwFlags,;
	STRING	@pbData,;
	LONG 	@pdwDataLen


*------------------- Pido el certificado P12, el documento XML a firmar, 
*------------------- la clave del certificado y el nombre de la persona a quien fue emitido

m.Certificado_p12	= GETFILE("P12")

m.ClaveCertificado	= SPACE(30)
m.NombreCertif		= SPACE(30)
@ 3,5 say "Digite la clave del certificado: " get m.ClaveCertificado pict "@X"
@ 5,5 say "A nombre de quien está el certificado: " get m.NombreCertif pict "@X" funct "!"
READ 

m.DocumentoXML = Crea_Factura()
m.DocFirmado   = FirmaDocumento(m.Certificado_p12, ALLTRIM(m.ClaveCertificado), ALLTRIM(m.NombreCertif), m.DocumentoXML)

CREATE CURSOR curDocumento (DocFirmado m(4))
INSERT INTO   curDocumento (DocFirmado) VALUES (m.DocFirmado)
BROWSE 

RETURN 

FUNCTION FirmaDocumento
PARAMETERS pCertificado_P12, pClaveCertificado, pNombreCertif, pDocumentoXML

* 1. Valido el archivo p12
StrPfx		 = FILETOSTR(pCertificado_P12)
cbData		 = LEN(StrPfx)
pbData		 = HeapAlloc(GetProcessHeap(), 0, cbData)
RtlMoveMemory(pbData, @StrPfx, cbData)
pPFX		 = 0h + BINTOC(cbData,"4RS") + BINTOC(pbData, "4RS")
IF PFXIsPFXBlob(pPFX)=0
	MESSAGEBOX( "El archivo no es un PFX/P12 válido")
	HeapFree(GetProcessHeap(), 0, pbData)
	RETURN ''
ENDIF

* 2. Verifico la clave del archivo p12
cPassword  = STRCONV(pClaveCertificado,5) + CHR(0)
IF PFXVerifyPassword(pPFX, cPassword, 0) = 0
	MESSAGEBOX("Contraseña incorrecta")
	HeapFree(GetProcessHeap(), 0, pbData)
	RETURN ''
ENDIF

*3. Importa los certificados
hStoreHandle = 0
hStoreHandle = PFXImportCertStore(pPFX, cPassword, CRYPT_EXPORTABLE)
cPassword = ""
pPFX = ""
HeapFree(GetProcessHeap(), 0, pbData)
IF hStoreHandle=0
	MESSAGEBOX("No se puede importar el certificado")
	RETURN ''
ENDIF

lnStoreProvider = CERT_STORE_PROV_SYSTEM
lcPara = Strconv("MY" + Chr(0), 5)
hStoreHandle = CertOpenStore(lnStoreProvider, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, lcPara)

hStore = hStoreHandle

*4. Busco el nombre del dueño del certificado
*PCCERT_CONTEXT CertFindCertificateInStore(
*1  [in] HCERTSTORE     hCertStore,
*2  [in] DWORD          dwCertEncodingType,
*3  [in] DWORD          dwFindFlags,
*4  [in] DWORD          dwFindType,
*5  [in] const void     *pvFindPara,
*6  [in] PCCERT_CONTEXT pPrevCertContext
lcFindPara = Strconv(pNombreCertif + Chr (0), 5)
*                                            1                   2                             3            4                5       6
m.Certificado = CertFindCertificateInStore(hStore,BITOR(PKCS_7_ASN_ENCODING, X509_ASN_ENCODING),0, CERT_FIND_SUBJECT_STR, lcFindPara, 0) 
IF m.Certificado = 0
	=CertCloseStore(hStore, 0) 
	=MESSAGEBOX("No encuentro ese nombre")
	RETURN ''
ENDIF

m.LfCr					= CHR(10)

* Número de serie
m.CertInfo 			= GetStructure_CertInfo(m.Certificado)
* STRCONV 15 Converts single-byte characters in cExpression to encoded hexBinary.
m.X509SerialNumber	= STRCONV(GetSerialNumber(m.CertInfo),15)

* Otros datos del certificado
m.bPublicKeyValue	= GetSubjectPublicKeyValue(m.CertInfo)
m.cPublicKeyInfo 	= GetSubjectPublicKeyInfo(m.CertInfo)
m.Exponente			= GetExponent(m.bPublicKeyValue)
m.Modulo			= STRCONV(GetModulus(bPublicKeyValue, SUBSTR(cPublicKeyInfo, 1, AT(";", cPublicKeyInfo)-1)),13)
m.Issuer			= GetIssuer(m.Certificado)
m.CertificateEncoded= STRCONV(GetCertificateEncoded(m.Certificado),13)

*5 Trabajar con el certificado
* Pasar certificado a formato PEM y sacar su hash
m.CertifX509_der_hash = GetCryptBinaryToString(m.CertificateEncoded, CRYPT_STRING_BASE64HEADER)

* quitar encabezado y pie y separarlo en lineas de 76 caracteres
m.CertifX509_der_hash = STREXTRACT(m.CertifX509_der_hash, CHR(13) + CHR(10))  &&--- se quita el encabezado
nPos = AT(CHR(13) + CHR(10)+'-----END CERTIFICATE-----', m.CertifX509_der_hash)
IF nPos > 0
	m.CertifX509_der_hash = SUBSTR(m.CertifX509_der_hash, 1, nPos - 1)  &&--- se quita el pie
ENDIF 

m.CertificateX509 = STRTRAN(m.CertifX509_der_hash, CHR(13) + CHR(10), '')
m.Lineas = INT(LEN(m.CertificateX509) / 76)
m.Certif76 = ''
FOR i = 1 TO m.Lineas
	m.Certif76 = m.Certif76 + SUBSTR(m.CertificateX509, IIF(i=1,1, ((i - 1) * 76) + 1), 76) + CHR(10)
ENDFOR 
IF m.Lineas * 76 < LEN(CertificateX509)
	m.Certif76 = m.Certif76 + SUBSTR(CertificateX509, (m.Lineas *76) + 1, LEN(CertificateX509) - (m.Lineas * 76)) + CHR(10)
ENDIF  
m.CertifX509_der_hash = m.Certif76
m.CertifX509_der_hash = GetDigestValue(m.CertifX509_der_hash, "SHA1")
* (13) Converts single-byte characters in cExpression to encoded base64 binary
m.CertifX509_der_hash = STRCONV(m.CertifX509_der_hash,13)

* Se convierte el certificado digital a una estructura de datos ASN.1
* certificateX509_asn1 = forge.pki.certificateToAsn1(cert);
* Se convierte la estructura ASN.1 del certificado a formato DER 
* certificateX509_der = forge.asn1.toDer(certificateX509_asn1).getBytes();
* Se calcula el hash SHA-1 en base64 del certificado DER 
* certificateX509_der_hash = sha1_base64(certificateX509_der);

* Converts single-byte characters in cExpression to encoded base64 binary
m.Sha1_Comprobante	= STRCONV(pDocumentoXML,13)

m.XmlNS 			= [xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:etsi="http://uri.etsi.org/01903/v1.3.2#"]

* Números involucrados en los hash
m.CertificaN	 	= ALLTRIM(STR(INT(RAND() * 1000000)))  && 1
m.SignatureN		= ALLTRIM(STR(INT(RAND() * 1000000)))  && 2
m.SignedPropN		= ALLTRIM(STR(INT(RAND() * 1000000)))  && 3

* Números fuera de los hash
m.SignedInfoN		= ALLTRIM(STR(INT(RAND() * 1000000)))  && 4
m.SignedPrID		= ALLTRIM(STR(INT(RAND() * 1000000)))  && 5
m.ReferenceID		= ALLTRIM(STR(INT(RAND() * 1000000)))  && 6
m.SignatureValue	= ALLTRIM(STR(INT(RAND() * 1000000)))  && 7
m.Object_Number		= ALLTRIM(STR(INT(RAND() * 1000000)))  && 8

* Fecha de la firma
m.Fecha					= DTOS(DATE())
m.FFirma				= SUBSTR(m.Fecha,1,4)+'-'+SUBSTR(m.Fecha,5,2)+'-'+SUBSTR(m.Fecha,7,2)
m.HFirma				= 'T'+TIME()
m.UTC					= '-05:00'  &&--- Ecuador

m.SignedProperties 	= ''
*Parte 4: Signed Properties ---------------------------------------------------------------
m.SignedProperties	= ''
m.SignedProperties = m.SignedProperties + '<etsi:SignedProperties Id="Signature'+m.SignatureN+'-SignedProperties'+m.SignedPropN+'">'
m.SignedProperties = m.SignedProperties + '<etsi:SignedSignatureProperties>'
m.SignedProperties = m.SignedProperties + '<etsi:SigningTime>'+ m.FFirma+ m.HFirma+ m.UTC+ '</etsi:SigningTime>'
m.SignedProperties = m.SignedProperties + '<etsi:SigningCertificate>'
m.SignedProperties = m.SignedProperties + '<etsi:Cert>'
m.SignedProperties = m.SignedProperties + '<etsi:CertDigest>'
m.SignedProperties = m.SignedProperties + '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
m.SignedProperties = m.SignedProperties + '<ds:DigestValue>'
m.SignedProperties = m.SignedProperties + m.CertifX509_der_hash
m.SignedProperties = m.SignedProperties + '</ds:DigestValue>'
m.SignedProperties = m.SignedProperties + '</etsi:CertDigest>'
m.SignedProperties = m.SignedProperties + '<etsi:IssuerSerial>'
m.SignedProperties = m.SignedProperties + '<ds:X509IssuerName>' +m.Issuer+ '</ds:X509IssuerName>'
m.SignedProperties = m.SignedProperties + '<ds:X509SerialNumber>'+ m.X509SerialNumber+ '</ds:X509SerialNumber>'
m.SignedProperties = m.SignedProperties + '</etsi:IssuerSerial>'
m.SignedProperties = m.SignedProperties + '</etsi:Cert>'
m.SignedProperties = m.SignedProperties + '</etsi:SigningCertificate>'
m.SignedProperties = m.SignedProperties + '</etsi:SignedSignatureProperties>'
m.SignedProperties = m.SignedProperties + '<etsi:SignedDataObjectProperties>'
m.SignedProperties = m.SignedProperties + '<etsi:DataObjectFormat ObjectReference="#Reference-ID-' +m.ReferenceID+ '">'
m.SignedProperties = m.SignedProperties + '<etsi:Description>contenido comprobante</etsi:Description>'
m.SignedProperties = m.SignedProperties + '<etsi:MimeType>text/xml</etsi:MimeType>'
m.SignedProperties = m.SignedProperties + '</etsi:DataObjectFormat>'
m.SignedProperties = m.SignedProperties + '</etsi:SignedDataObjectProperties>'
m.SignedProperties = m.SignedProperties + '</etsi:SignedProperties>'

*Haces el hash de Signed Properties
m.SignedPHash	= STRTRAN(m.SignedProperties, '<etsi:SignedProperties ', '<etsi:SignedProperties ' + m.XmlNS)
m.Sha1SignedP	= STRCONV(m.SignedPHash, 13)  &&--- base 64

*Parte 3: Key Info -----------------------------------------------------------------------
m.KeyInfo	= ''
m.KeyInfo	= m.KeyInfo + '<ds:KeyInfo Id="Certificate' + m.CertificaN + '">'
m.KeyInfo	= m.KeyInfo + m.LfCr + '<ds:X509Data>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '<ds:X509Certificate>' + m.LfCr
m.KeyInfo	= m.KeyInfo + m.CertificateEncoded
m.KeyInfo	= m.KeyInfo + m.LfCr + '</ds:X509Certificate>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '</ds:X509Data>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '<ds:KeyValue>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '<ds:RSAKeyValue>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '<ds:Modulus>' + m.LfCr
m.KeyInfo	= m.KeyInfo + m.Modulo &&--- módulo del certificado X509
m.KeyInfo	= m.KeyInfo + m.LfCr + '</ds:Modulus>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '<ds:Exponent>' +m.Exponente+ '</ds:Exponent>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '</ds:RSAKeyValue>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '</ds:KeyValue>'
m.KeyInfo	= m.KeyInfo + m.LfCr + '</ds:KeyInfo>'

*Haces el hash de Key Info
m.KeyInfoHash	= STRTRAN(m.KeyInfo, '<ds:KeyInfo', '<ds:KeyInfo ' + m.XmlNS)
m.Sha1_Certif	= STRCONV(m.KeyInfoHash, 13)


*Parte 1: Signed Info -----------------------------------------------------------------------
m.SignedInfo = ''
m.SignedInfo = m.SignedInfo + '<ds:SignedInfo Id="Signature-SignedInfo' + m.SignedInfoN + '">'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1">' + '</ds:SignatureMethod>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:Reference Id="SignedPropertiesID' + m.SignedPrID + '" Type="http://uri.etsi.org/01903#SignedProperties" URI="#Signature' + m.SignatureN + '-SignedProperties' + m.SignedPrID + '">'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1">'+'</ds:DigestMethod>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:DigestValue>'

m.SignedInfo = m.SignedInfo +          m.Sha1SignedP

m.SignedInfo = m.SignedInfo +          '</ds:DigestValue>'

m.SignedInfo = m.SignedInfo + m.LfCr + '</ds:Reference>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:Reference Id="Reference-ID-' + m.ReferenceID + '" URI="#comprobante">'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:Transforms>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature">' + '</ds:Transform>'
m.SignedInfo = m.SignedInfo + m.LfCr + '</ds:Transforms>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod>'
m.SignedInfo = m.SignedInfo + m.LfCr + '<ds:DigestValue>'
m.SignedInfo = m.SignedInfo + 		 m.Sha1_Comprobante
m.SignedInfo = m.SignedInfo + 		 '</ds:DigestValue>'
m.SignedInfo = m.SignedInfo + m.LfCr + '</ds:Reference>'
m.SignedInfo = m.SignedInfo + m.LfCr + '</ds:SignedInfo>'

* 6 Usar el certificado para firmar

m.SignedInfo_Para_Firma = STRTRAN(m.SignedInfo, '<ds:SignedInfo', '<ds:SignedInfo '+ m.XmlNS)
m.SignedInfo_Para_Firma = "Lo que se va a firmar"

tcParKey = GetPrivateKey(m.Certificado)
IF EMPTY(tcParKey)
	MESSAGEBOX("No se pudo exportar el par de claves. Tal vez está marcado como no exportable")
	=CertCloseStore(hStore, 0)
	RETURN ''
ENDIF

tcDataSign = GetDigestValue(m.SignedInfo_Para_Firma, "SHA1")   &&---- Digest value Sha1
IF EMPTY(tcDataSign)
	MESSAGEBOX("No se creó el hash")
	=CertCloseStore(hStore, 0)
	RETURN ''
ENDIF

tcSigned = GetSignHash(tcDataSign, tcParKey)    &&----- Signature 
IF EMPTY(tcSigned)
	MESSAGEBOX("No se firmó signed info")
	=CertCloseStore(hStore, 0)
	RETURN ''	
ENDIF
tcSigned = TRANSFORM(STRCONV(tcSigned,13))
=CertCloseStore(hStore, 0)  &&----- terminé de usar el certificado

m.Xades_Bes  = [<ds:Signature ] + m.XmlNS + [ Id="Signature] + m.SignatureN + [">] + m.LfCr

m.Xades_Bes  = m.Xades_Bes + m.SignedInfo + m.LfCr

m.Xades_Bes  = m.Xades_Bes + [<ds:SignatureValue Id="SignatureValue]+m.SignatureValue + [">] + m.LfCr
m.Xades_Bes  = m.Xades_Bes + tcSigned + m.LfCr
m.Xades_Bes  = m.Xades_Bes + [</ds:SignatureValue>] + m.LfCr

m.Xades_Bes  = m.Xades_Bes + m.KeyInfo + m.LfCr

m.Xades_Bes  = m.Xades_Bes + [<ds:Object Id="Signature] + m.SignatureN + [-Object] + m.Object_Number + [">] + m.LfCr
m.Xades_Bes  = m.Xades_Bes + [<etsi:QualifyingProperties Target="#Signature] + m.SignatureValue + [">] + m.LfCr

m.Xades_Bes  = m.Xades_Bes + m.SignedProperties + m.LfCr

m.Xades_Bes  = m.Xades_Bes + [</etsi:QualifyingProperties>] + m.LfCr
m.Xades_Bes  = m.Xades_Bes + [</ds:Object>] + m.LfCr
m.Xades_Bes  = m.Xades_Bes + [</ds:Signature>] + m.LfCr
m.Xades_Bes  = m.Xades_Bes + [</factura>]

RETURN pDocumentoXML + m.Xades_Bes
*----------------------- Fin de FirmaDocumento

FUNCTION Crea_Factura
TEXT TO m.Factura TEXTMERGE NOSHOW 
<factura id="comprobante" version="1.0.0">
 <infoTributaria>
    <ambiente>1</ambiente>
   <tipoEmision>1</tipoEmision>
   <razonSocial>CURTIEMBRE RENACIENTE S.A.</razonSocial>
   <nombreComercial>CURTIEMBRE RENACIENTE S.A.</nombreComercial>
   <ruc>0190004937001</ruc>
   <claveAcceso>0106202301019000493700110030020000049381234567811</claveAcceso>
   <codDoc>01</codDoc>
   <estab>003</estab>
   <ptoEmi>002</ptoEmi>
   <secuencial>000004938</secuencial>
   <dirMatriz>AV. PUMAPUNGO 18-123</dirMatriz>
  </infoTributaria>
 <infoFactura>
    <fechaEmision>01/06/2023</fechaEmision>
   <dirEstablecimiento>AV. C.J. AROSEMENA KM  2 1/2</dirEstablecimiento>
   <contribuyenteEspecial>5368</contribuyenteEspecial>
   <obligadoContabilidad>SI</obligadoContabilidad>
   <tipoIdentificacionComprador>04</tipoIdentificacionComprador>
   <razonSocialComprador>GOTELLI S.A.</razonSocialComprador>
   <identificacionComprador>0992284668001</identificacionComprador>
   <totalSinImpuestos>800.00</totalSinImpuestos>
   <totalDescuento>0.00</totalDescuento>
   <totalConImpuestos>
    <totalImpuesto>
     <codigo>2</codigo>
     <codigoPorcentaje>2</codigoPorcentaje>
     <baseImponible>800.00</baseImponible>
     <valor>96.00</valor>
    </totalImpuesto>
   </totalConImpuestos>
   <propina>0.00</propina>
   <importeTotal>896.00</importeTotal>
   <moneda>DOLAR</moneda>
  </infoFactura>
 <detalles>
  <detalle>
   <codigoPrincipal>PCPFOE12Q5P</codigoPrincipal>
   <descripcion>CUERO CUERO PERFORADO FORD EXPLORER 3F 2012 HABANO</descripcion>
   <cantidad>1.00</cantidad>
   <precioUnitario>800.0000</precioUnitario>
   <descuento>0.00</descuento>
   <precioTotalSinImpuesto>800.00</precioTotalSinImpuesto>
   <impuestos>
    <impuesto>
     <codigo>2</codigo>
     <codigoPorcentaje>2</codigoPorcentaje>
     <tarifa>12.00</tarifa>
     <baseImponible>800.00</baseImponible>
     <valor>96.00</valor>
    </impuesto>
   </impuestos>
  </detalle>
 </detalles>
 <infoAdicional>
    <campoAdicional nombre="Direccion">KENNEDY NORTE MZ 101 SOLAR #2  Y </campoAdicional>
   <campoAdicional nombre="Telefono">042290887</campoAdicional>
   <campoAdicional nombre="Email">gsistemas@renaciente.com</campoAdicional>
  </infoAdicional>
ENDTEXT 

RETURN m.Factura

PROCEDURE GetStructure_CertInfo()
	LPARAMETERS tpCertContext AS Long
	lbCertInfo	= SYS(2600, tpCertContext, 20)
	lpCertInfo 	= CTOBIN(SUBSTR(lbCertInfo, 13, 4), "4RS")
	lcCertInfo	= SYS(2600, lpCertInfo, 112)
	RETURN lcCertInfo
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

PROCEDURE GetReverseString()
	LPARAMETERS tcStringToReverse AS String 
	LOCAL lcReverse, nRev
	lcReverse=""
	FOR nRev = LEN(tcStringToReverse) TO 1 STEP -1
		lcReverse = lcReverse + SUBSTR(tcStringToReverse, nRev,1)
	NEXT
	RETURN lcReverse
ENDPROC

PROCEDURE GetExponent()
	LPARAMETERS tbPublicKey AS String
	cAsn1Exponent = RIGHT(tbPublicKey,3)
   * 13 = Converts single-byte characters in cExpression to encoded base64 binary.
	cB64Exponent = STRCONV(cAsn1Exponent,13)
	RETURN cB64Exponent
ENDPROC

PROCEDURE GetSubjectPublicKeyValue()
	LPARAMETERS tcCertInfo AS String
	lbPublicKey	 = SUBSTR(tcCertInfo,69,8)
	lnPublicKey = CTOBIN(SUBSTR(lbPublicKey, 1, 4),"4RS")
	lpPublicKey = CTOBIN(SUBSTR(lbPublicKey, 5, 4),"4RS")
	lcPublicKey = SYS(2600, lpPublicKey, lnPublicKey)
	RETURN lcPublicKey
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

PROCEDURE GetIssuer()
	LPARAMETERS tpCertContext AS Long
	lcIssuer = ""
	lpCertInfo  = CTOBIN(SYS(2600, tpCertContext + 12, 4), "4RS")
	IF lpCertInfo > 0
		lcIssuer = GetCertNameToString(lpCertInfo + 24)
	ENDIF
	RETURN lcIssuer
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

PROCEDURE GetCertNameToString()
	LPARAMETERS pbCertNameBlob AS Long
	*----- Valores posibles para wDwStrType, pueden ser la suma de varios
	SIMPLENAMESTR		= 1
	OIDNAMESTR			= 2
	X500NAMESTR			= 3
	SEMICOLONFLAG		= 0x40000000
	CRLFFLAG			= 0x08000000
	NOPLUSFLAG			= 0x20000000
	NOQUOTINGFLAG		= 0x10000000
	NAMEREVERSE			= 0x02000000
	DISABLEIE4UTF8		= 0x00010000
	ENABLEPUNYCODE		= 0x00200000

	*----- Asignamos valores a Parametros
	nCertEncodTyp 		= BITOR(PKCS_7_ASN_ENCODING, X509_ASN_ENCODING)
	cpName 		  		= pbCertNameBlob
	nDwStrType 	  		= BITOR(X500NAMESTR, OIDNAMESTR, NAMEREVERSE, SEMICOLONFLAG)
	lcNameDecoded 		= ""
	lnNameLong    		= 0
	*----- Intento 1, obtenemos longitud de cadena
	lnNameLong 			= CertNameToStr(nCertEncodTyp, cpName, nDwStrType, @lcNameDecoded, @lnNameLong)
	IF lnNameLong <> 0
		*----- Intento 2, conociendo longitud de cadena, Obtenemos el nombre decodificado
		lcNameDecoded	= REPLICATE(CHR(0), lnNameLong)
		CertNameToStr(nCertEncodTyp, cpName, nDwStrType, @lcNameDecoded, @lnNameLong)
	ENDIF
	*----- La función devuelve una cadena terminada en nulo, quitamos el CHR(0) que represanta nulo
	RETURN STRTRAN(lcNameDecoded, CHR(0), "")
ENDPROC

PROCEDURE GetCryptBinaryToString()
	LPARAMETERS tcStringToConvert AS String, tnHexorBase64 AS Integer
	lcRespStr = ""
	IF VARTYPE(tcStringToConvert)=="C" OR VARTYPE(tnHexorBase64)=="N"
		pbBinary = tcStringToConvert
		cbBinary = LEN(pbBinary)
		dwFlags = tnHexorBase64
		pcchString = 0
		pszString = ""
		nResp = CryptBinaryToString(@pbBinary, cbBinary, dwFlags, NULL, @pcchString)
		IF nResp>0
			pszString = SPACE(pcchString)
			nResp = CryptBinaryToString(@pbBinary, cbBinary, dwFlags, @pszString, @pcchString)
		ENDIF
		lcRespStr = pszString
	ENDIF
	RETURN lcRespStr
ENDPROC

PROCEDURE GetDigestValue(tcData, tcHashAlg)
	lnAlg = 0
	nRespBCOAP = BCryptOpenAlgorithmProvider(@lnAlg, STRCONV(tcHashAlg,5)+CHR(0), NULL, 0)
	IF nRespBCOAP<>0
		MESSAGEBOX("ERROR AL ABRIR ALGORITMO")
		RETURN ""
	ENDIF
	*----- Determinamos cuántos bytes necesitamos para almacenar el objeto hash
	lnSizeObj = 0 
	lnData = 0 
	nRespNCGP = BCryptGetProperty(lnAlg, STRCONV("ObjectLength",5)+CHR(0), @lnSizeObj, 4, @lnData, 0)
	IF nRespNCGP<>0
		MESSAGEBOX("ERROR AL OBTENER PROPIEDAD DE ENCRIPTACION")
		RETURN ""
	ENDIF
	*----- Determinamos la longitud de valor hash 
	lnSizeHash = 0 
	nRespNCGP = BCryptGetProperty(lnAlg, STRCONV("HashDigestLength",5)+CHR(0), @lnSizeHash, 4, @lnData, 0)
	IF nRespNCGP<>0
		MESSAGEBOX("ERROR AL OBTENER PROPIEDAD DE ENCRIPTACION")
		RETURN ""
	ENDIF
	*----- Creamos un objeto Hash
	LOCAL lnHash, lcHashObj 
	lnHash = 0 
	lcHashObj = SPACE(lnSizeObj) 
	nRespBCCH = BCryptCreateHash(lnAlg, @lnHash, @lcHashObj, lnSizeObj, NULL, 0, 0)
	IF nRespBCCH<>0
		MESSAGEBOX("ERROR AL CREAR OBJETO HASH")
		RETURN ""
	ENDIF
	*----- Para crear el valor hash agregamos datos al objeto hash. Puede repetir este paso según sea necesario
	nLenData = LEN(tcData)
	nRespBCHD = BCryptHashData(lnHash, tcData, nLenData, 0)	
	IF nRespBCHD<>0
		nRespBCHD = BCryptHashData(lnHash, tcData, nLenData, 0)
		IF nRespBCHD<>0
			=MESSAGEBOX(nRespBCHD)
			RETURN ""
		ENDIF
	ENDIF
	*----- Indicamos al objeto hash que hemos terminado. El algoritmo ahora calcula el valor de hash y lo devuelve. 
	lcHash = SPACE(lnSizeHash) 
	=BCryptFinishHash(lnHash, @lcHash, lnSizeHash, 0)
	IF lnAlg<>0
		BCryptCloseAlgorithmProvider(lnAlg, 0) 
	ENDIF 
	IF lnHash<>0 
		BCryptDestroyHash(lnHash) 
	ENDIF
	lcHash15 = STRCONV(lcHash,13) && HexBinary ~ 16 format 
	RETURN lcHash15
ENDPROC

PROCEDURE GetSignHash(tcDataSign, tcParKey)	
	lcSigned = ""
	lnAlg = 0
	lnRes = BCryptOpenAlgorithmProvider(@lnAlg, BCRYPT_RSA_ALGORITHM, NULL, 0)
	lnKey = 0
	lnRes = BCryptImportKeyPair(lnAlg, 0, LEGACY_RSAPRIVATE_BLOB, @lnKey, tcParKey, LEN(tcParKey), 0)
	IF lnRes = 0
		lnAlgoString = HeapAlloc(GetProcessHeap(), 0, LEN(BCRYPT_SHA1_ALGORITHM))
		IF lnAlgoString <> 0
			SYS(2600, lnAlgoString, LEN(BCRYPT_SHA1_ALGORITHM), BCRYPT_SHA1_ALGORITHM)
			lnSize = 0
			lnRes = BCryptSignHash(lnKey, @lnAlgoString, tcDataSign, LEN(tcDataSign), NULL, 0, @lnSize, 2)  &&--- 4-feb-2019
			IF lnRes = 0  &&---- Firmar
				lcSigned = SPACE(lnSize)
				lnRes = BCryptSignHash(lnKey, @lnAlgoString, tcDataSign, LEN(tcDataSign), @lcSigned, lnSize, @lnSize, 8)
				IF lnRes = 0  &&---- Si firmó
					lcSigned = LEFT(lcSigned, lnSize)
				ELSE  &&---- No firmó
					lcSigned = ""
				ENDIF
			ENDIF
			HeapFree(GetProcessHeap(), 0, lnAlgoString)
		ENDIF
		BCryptDestroyKey(lnKey)
	ENDIF
	BCryptCloseAlgorithmProvider(lnAlg, 0)
	RETURN lcSigned
ENDPROC

PROCEDURE GetPrivateKey(pCertContext)
	hCryptProv = 0
	dwKeySpec  = 0
	pfCFreProv = 0
	nResCPrivK = CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, 0, @hCryptProv, @dwKeySpec, @pfCFreProv)
	
	KEYBOARD '{ENTER}'
	phUserKey = 0
	nResCGUK = CryptGetUserKey(hCryptProv, dwKeySpec, @phUserKey)
	
	pdwDataLen = 0
	nRespEK = CryptExportKey(phUserKey , 0, PRIVATEKEYBLOB, 0, NULL, @pdwDataLen)
	pbData = SPACE(pdwDataLen)
	nRespEK = CryptExportKey(phUserKey , 0, PRIVATEKEYBLOB, 0, @pbData, @pdwDataLen)
	IF EMPTY(pbData)
		MESSAGEBOX("NO SE PUDO EXPORTAR EL PAR DE CLAVES")
	ENDIF
	RETURN pbData
ENDPROC