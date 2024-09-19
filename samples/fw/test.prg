#include "fivewin.ch"

function main()

   MsgInfo("Seleccionado certificado: "+ToTxt(SELCERT()), "CryptoApi")

return nil

//--------------------------------------------------------------------------//

static function ToTxt( uVal )

   local cType := ValType( uVal )

   do case
      case cType == "C" .or. cType == "M"
           return uVal

      case cType == "D"
           return DToC( uVal )

      case cType == "L"
           return If( uVal, ".T.", ".F." )

      case cType == "N"
           return AllTrim( Str( uVal ) )

      case cType == "B"
           return "{|| ... }"

      case cType == "A"
           return "{ ... }"

      case cType == "O"
           return If( __ObjHasData( uVal, "cClassName" ), uVal:cClassName, uVal:ClassName() )

      case cType == "H"
           return "{=>}"

      otherwise
           return ""
   endcase

return nil

//--------------------------------------------------------------------------//

#pragma BEGINDUMP

#include <windows.h>
#include <hbapi.h>
#include <wincrypt.h>

#define CRYPTUI_SELECT_LOCATION_COLUMN 0x000000010

// Definir el prototipo de las funciones
typedef HCERTSTORE (WINAPI * PTYPECERTOPEN) (HCRYPTPROV, LPTSTR);
typedef PCCERT_CONTEXT (WINAPI * PTYPECERTSELECTDLG) (HCERTSTORE, HWND, LPCWSTR, LPCWSTR, DWORD, DWORD, void*);
typedef PCCERT_CONTEXT (WINAPI * PTYPECERTENUM) (HCERTSTORE, PCCERT_CONTEXT);
typedef DWORD (WINAPI * PTYPECERTGETNAME) (PCCERT_CONTEXT, DWORD, DWORD, VOID*, LPTSTR, DWORD);
typedef DWORD (WINAPI * PTYPECERTNAMETOSTR) (DWORD, PCERT_NAME_BLOB, DWORD, LPTSTR, DWORD);
typedef BOOL (WINAPI * PTYPECERTFREECC) (PCCERT_CONTEXT);
typedef BOOL (WINAPI * PTYPECERTCLOSESTORE) (HCERTSTORE, DWORD);

HB_FUNC(SELCERT)
{

   // Hay varios ejemplos en: https://msdn.microsoft.com/en-us/librar ... 61(v=vs.85).aspx

   HCERTSTORE hStore;
   PCCERT_CONTEXT PrevContext, CurContext;
   PCHAR sNombre;
   DWORD cbSize;
   PHB_ITEM pArray;
   PHB_ITEM pItem;
   PCCERT_CONTEXT pCertContext;

   // Cargar las librerías de las que queremos la dirección de las funciones
   HMODULE HCrypt  = LoadLibrary("Crypt32.dll");
   HMODULE HCrypt2 = LoadLibrary("Cryptui.dll");

   // Declaramos el tipo de puntero a la función, tenemos la definición arriba.
   PTYPECERTOPEN    pCertOpen;
   PTYPECERTSELECTDLG    pCertSelectDlg;
   PTYPECERTGETNAME pCertGetName;
   PTYPECERTNAMETOSTR pCertNameToStr;
   PTYPECERTFREECC pCertFreeCC;
   PTYPECERTCLOSESTORE pCertCloseStore;


   if (HCrypt != NULL && HCrypt2 != NULL)
   {
      #ifdef UNICODE
         pCertOpen    = (PTYPECERTOPEN) GetProcAddress(HCrypt, "CertOpenSystemStoreW");
         pCertGetName = (PTYPECERTGETNAME) GetProcAddress(HCrypt, "CertGetNameStringW");
      #else
         pCertOpen    = (PTYPECERTOPEN) GetProcAddress(HCrypt, "CertOpenSystemStoreA");
         pCertGetName = (PTYPECERTGETNAME) GetProcAddress(HCrypt, "CertGetNameStringA");
      #endif
      pCertSelectDlg = (PTYPECERTSELECTDLG) GetProcAddress(HCrypt2, "CryptUIDlgSelectCertificateFromStore");
      pCertFreeCC  = (PTYPECERTFREECC) GetProcAddress(HCrypt, "CertFreeCertificateContext");
      pCertCloseStore  = (PTYPECERTCLOSESTORE) GetProcAddress(HCrypt, "CertCloseStore");
   }

   if (pCertOpen)
   {
      // Llamada al almacen de certificados
      hStore = pCertOpen(NULL, TEXT("MY"));
   }

   if (hStore)
   {
      pCertContext = pCertSelectDlg(hStore, NULL, NULL, NULL, CRYPTUI_SELECT_LOCATION_COLUMN, 0, NULL);

      if (pCertContext!=NULL)
      {
         cbSize = pCertGetName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);

         if (cbSize>0) 
         {
            sNombre = (LPTSTR)malloc(cbSize * sizeof(TCHAR));

            pCertGetName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, sNombre, cbSize);

            pCertFreeCC(pCertContext);
         }
      } else {
         sNombre = "";
      }

      // Cerrar el almacen de certificados
      pCertCloseStore(hStore, 0);
    }

    FreeLibrary(HCrypt);
    FreeLibrary(HCrypt2);

    hb_retc(sNombre);
}

#pragma ENDDUMP
 