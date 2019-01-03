# MapleStory v95 Client Analysis

Hello everyone welcome to our analysis on GMS v95.1
  - This document is a work in progress
  - This is not a professional document
  - The primary focus is on what I did to do to create localhost
  - There is too much for me to go into excruciating detail about
  - Please contribute if you'd like to know more !!!

## CSecurityClient
Class used to handle anti cheat integration
  - Houses HackShield related fields in this version
  - In other versions houses NGS and XignCode3 relations fields
  - Is a TSingleton<CSecurityClient>
  
In lots of places in the client usage of CSecurityClient looks like such:
```cpp
  if ( TSingleton<CSecurityClient>::IsInstantiated() )
  {
    TSingleton<CSecurityClient>::GetInstance();
    CSecurityClient::InitModule();
  }
```
PatchRetZero on IsInstantiated can save you lots of patches you'd have to do in other places otherwise.

Sometimes it checks the pointer directly though:
```cpp
  if ( TSingleton<CSecurityClient>::ms_pInstance )
    CSecurityClient::OnPacket(iPacket);
```

##### Class Pseudo

```cpp
// write access to const memory has been detected, the output may be wrong!
void __thiscall CSecurityClient::CSecurityClient(CSecurityClient *this)
{
  CSecurityClient *v1; // edi
  TSecType<int> *v2; // esi
  int v3; // eax
  char v4; // dl
  TSecData<int> *v5; // ecx
  int v6; // eax
  TSecData<int> *v7; // edx
  int v8; // eax
  char v9; // cl

  v1 = this;
  v2 = &this->m_bInitModule;
  if ( this == (CSecurityClient *)-4 )
    TSingleton<CSecurityClient>::ms_pInstance = 0;
  else
    TSingleton<CSecurityClient>::ms_pInstance = this;
  this->vfptr = (CSecurityClientVtbl *)&CSecurityClient::`vftable';
  this->m_bInitModule.m_secdata = (TSecData<int> *)ZAllocEx<ZAllocAnonSelector>::Alloc(
                                                     &ZAllocEx<ZAllocAnonSelector>::_s_alloc,
                                                     0xCu);
  v2->FakePtr1 = (unsigned int)&v2[-1365].FakePtr2 + rand();
  v3 = rand();
  v4 = v2->FakePtr1;
  v5 = v2->m_secdata;
  v2->FakePtr2 = (unsigned int)&v2[-1365].FakePtr2 + v3;
  v5->FakePtr1 = v4;
  v2->m_secdata->FakePtr2 = v2->FakePtr2;
  TSecType<int>::SetData(v2, 0);
  v1->m_bStartModule.m_secdata = (TSecData<int> *)ZAllocEx<ZAllocAnonSelector>::Alloc(
                                                    &ZAllocEx<ZAllocAnonSelector>::_s_alloc,
                                                    0xCu);
  v1->m_bStartModule.FakePtr1 = (unsigned int)&v1[-52].m_szHShieldPath[rand() + 20];
  v6 = rand();
  v7 = v1->m_bStartModule.m_secdata;
  v1->m_bStartModule.FakePtr2 = (unsigned int)&v1[-52].m_szHShieldPath[v6 + 20];
  v7->FakePtr1 = v1->m_bStartModule.FakePtr1;
  v1->m_bStartModule.m_secdata->FakePtr2 = v1->m_bStartModule.FakePtr2;
  TSecType<int>::SetData(&v1->m_bStartModule, 0);
  v1->m_nThreatCode = 0;
  v1->m_nThreatParamSize.m_secdata = (TSecData<long> *)ZAllocEx<ZAllocAnonSelector>::Alloc(
                                                         &ZAllocEx<ZAllocAnonSelector>::_s_alloc,
                                                         0xCu);
  v1->m_nThreatParamSize.FakePtr1 = (unsigned int)&v1[-52].m_szHShieldPath[rand() + 36];
  v8 = rand();
  v9 = v1->m_nThreatParamSize.FakePtr1;
  v1->m_nThreatParamSize.FakePtr2 = (unsigned int)&v1[-52].m_szHShieldPath[v8 + 36];
  v1->m_nThreatParamSize.m_secdata->FakePtr1 = v9;
  v1->m_nThreatParamSize.m_secdata->FakePtr2 = v1->m_nThreatParamSize.FakePtr2;
  TSecType<long>::SetData(&v1->m_nThreatParamSize, 0);
  v1->m_pThreatParam = 0;
  v1->m_hMainWnd = 0;
}
void __thiscall CSecurityClient::InitModule(CSecurityClient *this)
{
  CSecurityClient *v1; // esi
  unsigned int v2; // eax
  int v3; // eax
  int (__stdcall **pExceptionObject)(ZXString<char> *); // [esp+4h] [ebp-214h]
  unsigned int v5; // [esp+8h] [ebp-210h]
  CHAR sModulePath; // [esp+Ch] [ebp-20Ch]
  char v7; // [esp+Dh] [ebp-20Bh]
  unsigned __int8 sModuleFolderPath; // [esp+110h] [ebp-108h]
  char v9; // [esp+111h] [ebp-107h]

  v1 = this;
  sModuleFolderPath = 0;
  memset(&v9, 0, 0x103u);
  sModulePath = 0;
  memset(&v7, 0, 0x103u);
  GetModuleFolderName((char *)&sModuleFolderPath);
  _mbsnbcpy((unsigned __int8 *)&sModulePath, &sModuleFolderPath, 0x104u);
  _mbsnbcat((unsigned __int8 *)&sModulePath, "\\HShield", 8u);
  _mbsnbcpy((unsigned __int8 *)v1->m_szHShieldPath, (const unsigned __int8 *)&sModulePath, 0x104u);
  v2 = _AhnHS_HSUpdateA(&sModulePath, 600000u, 20000u);
  if ( v2 )
  {
    v5 = v2;
    pExceptionObject = CSecurityUpdateFailed::`vftable';
    _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityUpdateFailed__);
  }
  _mbsnbcpy((unsigned __int8 *)&sModulePath, &sModuleFolderPath, 0x104u);
  _mbsnbcat((unsigned __int8 *)&sModulePath, "\\HShield\\EHSvc.dll", 0x12u);
  v3 = _AhnHS_InitializeA(&sModulePath, (int)_AhnHS_Callback, 9947, (int)"B7621D704ED72C489EE54605", 46808511, 1);
  if ( v3 )
  {
    v5 = v3;
    pExceptionObject = CSecurityInitFailed::`vftable';
    _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityInitFailed__);
  }
  TSecType<int>::SetData(&v1->m_bInitModule, 1);
}
void __thiscall CSecurityClient::ClearModule(CSecurityClient *this)
{
  TSecType<int> *v1; // esi
  signed int v2; // eax
  int (__stdcall **pExceptionObject)(ZXString<char> *); // [esp+4h] [ebp-8h]
  int v4; // [esp+8h] [ebp-4h]

  v1 = &this->m_bInitModule;
  if ( TSecType<int>::GetData(&this->m_bInitModule) )
  {
    v2 = _AhnHS_Uninitialize();
    if ( v2 )
    {
      v4 = v2;
      pExceptionObject = CSecurityClearFailed::`vftable';
      _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityClearFailed__);
    }
    TSecType<int>::SetData(v1, 0);
  }
}
void __thiscall CSecurityClient::StartModule(CSecurityClient *this)
{
  CSecurityClient *v1; // esi
  signed int v2; // eax
  int (__stdcall **v3)(ZXString<char> *); // [esp+0h] [ebp-Ch]
  int v4; // [esp+4h] [ebp-8h]

  v1 = this;
  v2 = _AhnHS_StartService();
  if ( v2 )
  {
    v4 = v2;
    v3 = CSecurityInitFailed::`vftable';
    _CxxThrowException(&v3, &_TI2_AVCSecurityInitFailed__);
  }
  _AhnHS_CheckHackShieldRunningStatus();
  v1->m_dwCallbackTime = GetTickCount();
  TSecType<int>::SetData(&v1->m_bStartModule, 1);
}
void __thiscall CSecurityClient::StopModule(CSecurityClient *this)
{
  TSecType<int> *v1; // esi
  signed int v2; // eax
  int (__stdcall **pExceptionObject)(ZXString<char> *); // [esp+4h] [ebp-8h]
  int v4; // [esp+8h] [ebp-4h]

  v1 = &this->m_bStartModule;
  if ( TSecType<int>::GetData(&this->m_bStartModule) )
  {
    v2 = _AhnHS_StopService();
    if ( v2 )
    {
      v4 = v2;
      pExceptionObject = CSecurityClearFailed::`vftable';
      _CxxThrowException(&pExceptionObject, &_TI2_AVCSecurityClearFailed__);
    }
    TSecType<int>::SetData(v1, 0);
  }
}

//Just throws an exception if HS error code is set
//Checks CSecurityClient->m_nThreatCode is a bad HS return code and throw ( result > 0x10501 )
signed int __thiscall CSecurityClient__Update(_DWORD *this)
{
  signed int result; // eax
  bool v2; // zf
  bool v3; // sf
  unsigned __int8 v4; // of
  int (__stdcall **v5)(int); // [esp+0h] [ebp-8h]
  int v6; // [esp+4h] [ebp-4h]

  result = this[7];
  if ( result > 0x10501 )
  {
    if ( result > 0x10801 )
    {
      if ( result != 0x10A01 )
        return result;
LABEL_18:
      v6 = this[7];
      v5 = &off_BF643C;
      sub_A68B61((int)&v5, &_TI2_AVCSecurityThreatDetected__);
      JUMPOUT(*(_DWORD *)algn_A52B42);
    }
    if ( result == 0x10801 || result == 67073 )
      goto LABEL_18;
    if ( result <= 0x10700 )
      return result;
    v4 = __OFSUB__(result, 67333);
    v2 = result == 67333;
    v3 = result - 67333 < 0;
LABEL_10:
    if ( !((unsigned __int8)(v3 ^ v4) | v2) )
      return result;
    goto LABEL_18;
  }
  if ( result == 0x10501 )
    goto LABEL_18;
  if ( result > 0x10303 )
  {
    if ( result < 0x10306 )
      return result;
    v4 = __OFSUB__(result, 66312);
    v2 = result == 66312;
    v3 = result - 66312 < 0;
    goto LABEL_10;
  }
  if ( result >= 0x10301 || result == 0x10102 || result == 0x10104 )
    goto LABEL_18;
  return result;
}
```

## IP Checks
  - Game is booby trapped with IP checks
  - It's not worth me pointing out where they all are ( will eventually )
  - But basically getpeername is called, just return the expected IP ` 63.251.217.1 `
  - Sad thing is they have heavy API checks on winsock so use the WSP variants like I do
  - TODO: Talk more about the ` MyGetProcAddress ` and heavy winapi checks ( xxxx.nst )

## CWvsApp Checks
  - ` CSecurityClient::Update ` is called in  ` CWvsApp::Run `
  - ` CWvsApp->m_tLastServerIPCheck ` is in ` CWvsApp::CallUpdate ` ( g_fnSafeGetPeerName check )
  - ` CWvsApp->m_tLastServerIPCheck2 ` is in ` CWvsApp::Run `  | Also contains CSecurityClient right below
  - ` CWvsApp->m_tLastSecurityCheck ` is in ` CWvsApp::Run `

#### Additional CSecurityClient Check
This is inside m_tLastServerIPCheck2
Checks some files readability HShield folder exist `3N.mhe, v3warpds.v3d, v3warpns.v3d ` (Check ` GetLastError` below)
Checks ` _AhnHS_StartSerice ` ret and expects `HS_ERR_ALREADY_SERVICE_RUNNING` ( 0x00000201 )
Checks `CSecurityClient->m_dwCallbackTime` is ` <= 60000 `

```cpp
    if ( TSingleton_CSecurityClient__IsInstantiated() )
    {
      v22 = '\x01';
      v15 = '3';
      v16 = 'N';
      v17 = '.';
      v18 = 'm';
      v19 = 'h';
      v20 = 'e';
      v21 = '\0';
      v25 = 'v';
      v26 = '3';
      v27 = 'w';
      v28 = 'a';
      v29 = 'r';
      v30 = 'p';
      v31 = 'd';
      v32 = 's';
      v33 = '.';
      v34 = 'v';
      v35 = '3';
      v36 = 'd';
      v37 = '\0';
      v10 = TSingleton_CSecurityClient__GetInstance();
      sub_A6A463(&FileName, "%s\\%s", v10 + 52);
      hObject = CreateFileA(&FileName, 0x40000000u, 0, 0, 3u, 0, 0);
      if ( GetLastError() != 32 )
        v22 = 0;
      if ( hObject != (HANDLE)-1 )
        CloseHandle(hObject);
      if ( _AhnHS_StartService() != 513 )
        v22 = 0;
      v11 = GetTickCount();
      if ( v11 - *(_DWORD *)(TSingleton_CSecurityClient__GetInstance() + 48) > 60000 )
        v22 = 0;
    }
```
Relevant HS callback to above
```cpp

int __stdcall _AhnHS_Callback(int lCode, int lParamSize, void *pParam)
{
  if ( lCode == 65537 )
  {
    if ( TSingleton<CSecurityClient>::ms_pInstance )
    {
      TSingleton<CSecurityClient>::ms_pInstance->m_dwCallbackTime = GetTickCount();
      return 0;
    }
  }
  else if ( TSingleton<CSecurityClient>::ms_pInstance )
  {
    TSingleton<CSecurityClient>::ms_pInstance->m_nThreatCode = lCode;
    TSecType<long>::SetData(&TSingleton<CSecurityClient>::ms_pInstance->m_nThreatParamSize, lParamSize);
    TSingleton<CSecurityClient>::ms_pInstance->m_pThreatParam = pParam;
  }
  return 0;
}

```

#### CWvsApp->m_tLastSecurityCheck

MSCRC Checking Routine followed by CHECK_SEND_PACKET

v95 Pre Code Check ( Actual Segment is stripped from our v95 cleaned )
```
_text:009C6DCA DD8 8B 85 84 F2 FF FF                             mov     eax, [ebp+this]
_text:009C6DD0 DD8 8B 8D 44 FF FF FF                             mov     ecx, [ebp+tCurTime]
_text:009C6DD6 DD8 2B 48 64                                      sub     ecx, [eax+64h] //m_tLastSecurityCheck
_text:009C6DD9 DD8 8B 95 40 FF FF FF                             mov     edx, [ebp+rand]
_text:009C6DDF DD8 6B D2 0F                                      imul    edx, 15
_text:009C6DE2 DD8 69 D2 E8 03 00 00                             imul    edx, 1000
_text:009C6DE8 DD8 39 D1                                         cmp     ecx, edx
_text:009C6DEA DD8 E9 78 05 00 00                                jmp     loc_9C7367 //Patch jump over MSCRC checks
```

v97 Pseudo UNVMed Block ( Sets of 25 nops is the CLIENT_DEATH_MACRO)
```
___:009FA695 EB 1F                                   jmp     short loc_9FA6B6
___:009FA697                         ; ---------------------------------------------------------------------------
___:009FA697
___:009FA697                         loc_9FA697:                             ; CODE XREF: CWvsApp__Run+AE9↑j
___:009FA697 83 BD 50 FF FF FF 0F                    cmp     [ebp+var_B0], 0Fh
___:009FA69E 7C 0C                                   jl      short loc_9FA6AC
___:009FA6A0 C7 85 50 FF FF FF 02 00+                mov     [ebp+var_B0], 2
___:009FA6AA EB 0A                                   jmp     short loc_9FA6B6
___:009FA6AC                         ; ---------------------------------------------------------------------------
___:009FA6AC
___:009FA6AC                         loc_9FA6AC:                             ; CODE XREF: CWvsApp__Run+AFE↑j
___:009FA6AC C7 85 50 FF FF FF 01 00+                mov     [ebp+var_B0], 1
___:009FA6B6
___:009FA6B6                         loc_9FA6B6:                             ; CODE XREF: CWvsApp__Run+AF5↑j
___:009FA6B6                                                                 ; CWvsApp__Run+B0A↑j
___:009FA6B6 8B 8D A4 F2 FF FF                       mov     ecx, [ebp+var_D5C]
___:009FA6BC 8B 95 54 FF FF FF                       mov     edx, [ebp+var_AC]
___:009FA6C2 2B 51 64                                sub     edx, [ecx+64h]
___:009FA6C5 8B 85 50 FF FF FF                       mov     eax, [ebp+var_B0]
___:009FA6CB 6B C0 0F                                imul    eax, 0Fh
___:009FA6CE 69 C0 E8 03 00 00                       imul    eax, 3E8h
___:009FA6D4 39 C2                                   cmp     edx, eax
___:009FA6D6 0F 8E 8F 07 00 00                       jle     loc_9FAE6B
___:009FA6DC 8B 8D A4 F2 FF FF                       mov     ecx, [ebp+var_D5C]
___:009FA6E2 8B 95 54 FF FF FF                       mov     edx, [ebp+var_AC]
___:009FA6E8 89 51 64                                mov     [ecx+64h], edx
___:009FA6EB C7 85 38 FF FF FF 00 00+                mov     [ebp+var_C8], 0
___:009FA6F5 C7 85 48 FF FF FF 00 00+                mov     [ebp+var_B8], 0
___:009FA6FF C7 85 34 FF FF FF 01 00+                mov     [ebp+var_CC], 1
___:009FA709 C7 85 4C FF FF FF 00 00+                mov     [ebp+var_B4], 0
___:009FA713 8B 45 E0                                mov     eax, [ebp+var_20]
___:009FA716 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FA71B 89 45 E0                                mov     [ebp+var_20], eax
___:009FA71E 8B 45 E0                                mov     eax, [ebp+var_20]
___:009FA721 31 D2                                   xor     edx, edx
___:009FA723 B9 03 00 00 00                          mov     ecx, 3
___:009FA728 F7 F1                                   div     ecx
___:009FA72A 89 55 E0                                mov     [ebp+var_20], edx
___:009FA72D C7 85 3C FF FF FF 00 00+                mov     [ebp+var_C4], 0
___:009FA737 C7 85 44 FF FF FF 00 00+                mov     [ebp+var_BC], 0
___:009FA741 C7 85 40 FF FF FF 00 00+                mov     [ebp+var_C0], 0
___:009FA74B 83 7D E0 00                             cmp     [ebp+var_20], 0
___:009FA74F 0F 85 61 02 00 00                       jnz     loc_9FA9B6
___:009FA755 C7 85 38 FF FF FF FF FF+                mov     [ebp+var_C8], 0FFFFFFFFh
___:009FA75F C7 85 48 FF FF FF 53 89+                mov     [ebp+var_B8], 0CA218953h
___:009FA769 C7 85 34 FF FF FF 6C 58+                mov     [ebp+var_CC], 395A586Ch
___:009FA773 8B 55 E4                                mov     edx, [ebp+var_1C]
___:009FA776 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA77C 89 55 E4                                mov     [ebp+var_1C], edx
___:009FA77F 8B 45 E4                                mov     eax, [ebp+var_1C]
___:009FA782 05 00 00 40 00                          add     eax, 400000h
___:009FA787 89 85 3C FF FF FF                       mov     [ebp+var_C4], eax
___:009FA78D 8B 4D E4                                mov     ecx, [ebp+var_1C]
___:009FA790 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FA796 89 4D E4                                mov     [ebp+var_1C], ecx
___:009FA799 8B 55 B0                                mov     edx, [ebp+var_50]
___:009FA79C 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA7A2 89 55 B0                                mov     [ebp+var_50], edx
___:009FA7A5 C7 85 4C FF FF FF 08 37+                mov     [ebp+var_B4], 18253708h
___:009FA7AF C7 05 80 52 CC 00 00 00+                mov     g_bCallAuth_Maybe, 0
___:009FA7B9 8B 85 34 FF FF FF                       mov     eax, [ebp+var_CC]
___:009FA7BF 50                                      push    eax
___:009FA7C0 8D 8D 38 FF FF FF                       lea     ecx, [ebp+var_C8]
___:009FA7C6 51                                      push    ecx
___:009FA7C7 8B 95 48 FF FF FF                       mov     edx, [ebp+var_B8]
___:009FA7CD 52                                      push    edx
___:009FA7CE 8D 85 4C FF FF FF                       lea     eax, [ebp+var_B4]
___:009FA7D4 50                                      push    eax
___:009FA7D5 8B 4D B0                                mov     ecx, [ebp+var_50]
___:009FA7D8 51                                      push    ecx
___:009FA7D9 8B 95 3C FF FF FF                       mov     edx, [ebp+var_C4]
___:009FA7DF 52                                      push    edx
___:009FA7E0 E8 0B A2 08 00                          call    Crc32_GetCrc32
___:009FA7E5 83 C4 18                                add     esp, 18h
___:009FA7E8 89 85 40 FF FF FF                       mov     [ebp+var_C0], eax
___:009FA7EE 83 BD 40 FF FF FF 00                    cmp     [ebp+var_C0], 0
___:009FA7F5 74 15                                   jz      short loc_9FA80C
___:009FA7F7 81 BD 4C FF FF FF 10 12+                cmp     [ebp+var_B4], 101210h
___:009FA801 75 09                                   jnz     short loc_9FA80C
___:009FA803 83 3D 80 52 CC 00 01                    cmp     g_bCallAuth_Maybe, 1
___:009FA80A 74 33                                   jz      short loc_9FA83F
___:009FA80C
___:009FA80C                         loc_9FA80C:                             ; CODE XREF: CWvsApp__Run+C55↑j
___:009FA80C                                                                 ; CWvsApp__Run+C61↑j
___:009FA80C 68 68 4C BF 00                          push    offset aCrashCode ; "Crash CODE" //Manually added
___:009FA811 E8 8A A8 FF FF                          call    sub_9F50A0
___:009FA816 83 C4 04                                add     esp, 4
___:009FA819 90                                      nop
___:009FA81A 90                                      nop
___:009FA81B 90                                      nop
___:009FA81C 90                                      nop
___:009FA81D 90                                      nop
___:009FA81E 90                                      nop
___:009FA81F 90                                      nop
___:009FA820 90                                      nop
___:009FA821 90                                      nop
___:009FA822 90                                      nop
___:009FA823 90                                      nop
___:009FA824 90                                      nop
___:009FA825 90                                      nop
___:009FA826 90                                      nop
___:009FA827 90                                      nop
___:009FA828 90                                      nop
___:009FA829 90                                      nop
___:009FA82A 90                                      nop
___:009FA82B 90                                      nop
___:009FA82C 90                                      nop
___:009FA82D 90                                      nop
___:009FA82E 90                                      nop
___:009FA82F 90                                      nop
___:009FA830 90                                      nop
___:009FA831 90                                      nop
___:009FA832 90                                      nop
___:009FA833 90                                      nop
___:009FA834 90                                      nop
___:009FA835 90                                      nop
___:009FA836 90                                      nop
___:009FA837 90                                      nop
___:009FA838 90                                      nop
___:009FA839 90                                      nop
___:009FA83A 90                                      nop
___:009FA83B 90                                      nop
___:009FA83C 90                                      nop
___:009FA83D 90                                      nop
___:009FA83E 90                                      nop
___:009FA83F
___:009FA83F                         loc_9FA83F:                             ; CODE XREF: CWvsApp__Run+C6A↑j
___:009FA83F 8B 45 E4                                mov     eax, [ebp+var_1C]
___:009FA842 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FA847 89 45 E4                                mov     [ebp+var_1C], eax
___:009FA84A 8B 4D B0                                mov     ecx, [ebp+var_50]
___:009FA84D 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FA853 89 4D B0                                mov     [ebp+var_50], ecx
___:009FA856 8B 95 68 FF FF FF                       mov     edx, [ebp+var_98]
___:009FA85C 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA862 89 95 68 FF FF FF                       mov     [ebp+var_98], edx
___:009FA868 8B 85 74 FF FF FF                       mov     eax, [ebp+var_8C]
___:009FA86E 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FA873 89 85 74 FF FF FF                       mov     [ebp+var_8C], eax
___:009FA879 8B 4D DC                                mov     ecx, [ebp+var_24]
___:009FA87C 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FA882 89 4D DC                                mov     [ebp+var_24], ecx
___:009FA885 8B 95 7C FF FF FF                       mov     edx, [ebp+var_84]
___:009FA88B 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA891 89 95 7C FF FF FF                       mov     [ebp+var_84], edx
___:009FA897 8B 85 40 FF FF FF                       mov     eax, [ebp+var_C0]
___:009FA89D 3B 45 E4                                cmp     eax, [ebp+var_1C]
___:009FA8A0 72 0E                                   jb      short loc_9FA8B0
___:009FA8A2 8B 4D E4                                mov     ecx, [ebp+var_1C]
___:009FA8A5 03 4D B0                                add     ecx, [ebp+var_50]
___:009FA8A8 39 8D 40 FF FF FF                       cmp     [ebp+var_C0], ecx
___:009FA8AE 72 48                                   jb      short loc_9FA8F8
___:009FA8B0
___:009FA8B0                         loc_9FA8B0:                             ; CODE XREF: CWvsApp__Run+D00↑j
___:009FA8B0 8B 95 40 FF FF FF                       mov     edx, [ebp+var_C0]
___:009FA8B6 3B 95 68 FF FF FF                       cmp     edx, [ebp+var_98]
___:009FA8BC 72 14                                   jb      short loc_9FA8D2
___:009FA8BE 8B 85 68 FF FF FF                       mov     eax, [ebp+var_98]
___:009FA8C4 03 85 74 FF FF FF                       add     eax, [ebp+var_8C]
___:009FA8CA 39 85 40 FF FF FF                       cmp     [ebp+var_C0], eax
___:009FA8D0 72 26                                   jb      short loc_9FA8F8
___:009FA8D2
___:009FA8D2                         loc_9FA8D2:                             ; CODE XREF: CWvsApp__Run+D1C↑j
___:009FA8D2 90                                      nop
___:009FA8D3 90                                      nop
___:009FA8D4 90                                      nop
___:009FA8D5 90                                      nop
___:009FA8D6 90                                      nop
___:009FA8D7 90                                      nop
___:009FA8D8 90                                      nop
___:009FA8D9 90                                      nop
___:009FA8DA 90                                      nop
___:009FA8DB 90                                      nop
___:009FA8DC 90                                      nop
___:009FA8DD 90                                      nop
___:009FA8DE 90                                      nop
___:009FA8DF 90                                      nop
___:009FA8E0 90                                      nop
___:009FA8E1 90                                      nop
___:009FA8E2 90                                      nop
___:009FA8E3 90                                      nop
___:009FA8E4 90                                      nop
___:009FA8E5 90                                      nop
___:009FA8E6 90                                      nop
___:009FA8E7 90                                      nop
___:009FA8E8 90                                      nop
___:009FA8E9 90                                      nop
___:009FA8EA 90                                      nop
___:009FA8EB 90                                      nop
___:009FA8EC 90                                      nop
___:009FA8ED 90                                      nop
___:009FA8EE 90                                      nop
___:009FA8EF 90                                      nop
___:009FA8F0 90                                      nop
___:009FA8F1 90                                      nop
___:009FA8F2 90                                      nop
___:009FA8F3 90                                      nop
___:009FA8F4 90                                      nop
___:009FA8F5 90                                      nop
___:009FA8F6 90                                      nop
___:009FA8F7 90                                      nop
___:009FA8F8
___:009FA8F8                         loc_9FA8F8:                             ; CODE XREF: CWvsApp__Run+D0E↑j
___:009FA8F8                                                                 ; CWvsApp__Run+D30↑j
___:009FA8F8 8B 4D E4                                mov     ecx, [ebp+var_1C]
___:009FA8FB 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FA901 89 4D E4                                mov     [ebp+var_1C], ecx
___:009FA904 8B 55 B0                                mov     edx, [ebp+var_50]
___:009FA907 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA90D 89 55 B0                                mov     [ebp+var_50], edx
___:009FA910 8B 85 68 FF FF FF                       mov     eax, [ebp+var_98]
___:009FA916 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FA91B 89 85 68 FF FF FF                       mov     [ebp+var_98], eax
___:009FA921 8B 8D 74 FF FF FF                       mov     ecx, [ebp+var_8C]
___:009FA927 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FA92D 89 8D 74 FF FF FF                       mov     [ebp+var_8C], ecx
___:009FA933 8B 55 DC                                mov     edx, [ebp+var_24]
___:009FA936 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA93C 89 55 DC                                mov     [ebp+var_24], edx
___:009FA93F 8B 85 7C FF FF FF                       mov     eax, [ebp+var_84]
___:009FA945 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FA94A 89 85 7C FF FF FF                       mov     [ebp+var_84], eax
___:009FA950 8B 4D B0                                mov     ecx, [ebp+var_50]
___:009FA953 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FA959 89 4D B0                                mov     [ebp+var_50], ecx
___:009FA95C 8B 55 DC                                mov     edx, [ebp+var_24]
___:009FA95F 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA965 89 55 DC                                mov     [ebp+var_24], edx
___:009FA968 8B 85 38 FF FF FF                       mov     eax, [ebp+var_C8]
___:009FA96E 35 90 11 52 81                          xor     eax, 81521190h
___:009FA973 89 85 38 FF FF FF                       mov     [ebp+var_C8], eax
___:009FA979 8B 4D DC                                mov     ecx, [ebp+var_24]
___:009FA97C 3B 8D 38 FF FF FF                       cmp     ecx, [ebp+var_C8]
___:009FA982 74 26                                   jz      short loc_9FA9AA
___:009FA984 90                                      nop
___:009FA985 90                                      nop
___:009FA986 90                                      nop
___:009FA987 90                                      nop
___:009FA988 90                                      nop
___:009FA989 90                                      nop
___:009FA98A 90                                      nop
___:009FA98B 90                                      nop
___:009FA98C 90                                      nop
___:009FA98D 90                                      nop
___:009FA98E 90                                      nop
___:009FA98F 90                                      nop
___:009FA990 90                                      nop
___:009FA991 90                                      nop
___:009FA992 90                                      nop
___:009FA993 90                                      nop
___:009FA994 90                                      nop
___:009FA995 90                                      nop
___:009FA996 90                                      nop
___:009FA997 90                                      nop
___:009FA998 90                                      nop
___:009FA999 90                                      nop
___:009FA99A 90                                      nop
___:009FA99B 90                                      nop
___:009FA99C 90                                      nop
___:009FA99D 90                                      nop
___:009FA99E 90                                      nop
___:009FA99F 90                                      nop
___:009FA9A0 90                                      nop
___:009FA9A1 90                                      nop
___:009FA9A2 90                                      nop
___:009FA9A3 90                                      nop
___:009FA9A4 90                                      nop
___:009FA9A5 90                                      nop
___:009FA9A6 90                                      nop
___:009FA9A7 90                                      nop
___:009FA9A8 90                                      nop
___:009FA9A9 90                                      nop
___:009FA9AA
___:009FA9AA                         loc_9FA9AA:                             ; CODE XREF: CWvsApp__Run+DE2↑j
___:009FA9AA 8B 55 DC                                mov     edx, [ebp+var_24]
___:009FA9AD 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FA9B3 89 55 DC                                mov     [ebp+var_24], edx
___:009FA9B6
___:009FA9B6                         loc_9FA9B6:                             ; CODE XREF: CWvsApp__Run+BAF↑j
___:009FA9B6 83 7D E0 02                             cmp     [ebp+var_20], 2
___:009FA9BA 0F 85 7F 02 00 00                       jnz     loc_9FAC3F
___:009FA9C0 C7 85 38 FF FF FF FF FF+                mov     [ebp+var_C8], 0FFFFFFFFh
___:009FA9CA C7 85 48 FF FF FF 53 89+                mov     [ebp+var_B8], 0CA218953h
___:009FA9D4 C7 85 34 FF FF FF 6C 58+                mov     [ebp+var_CC], 395A586Ch
___:009FA9DE 8B 85 68 FF FF FF                       mov     eax, [ebp+var_98]
___:009FA9E4 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FA9E9 89 85 68 FF FF FF                       mov     [ebp+var_98], eax
___:009FA9EF 8B 8D 68 FF FF FF                       mov     ecx, [ebp+var_98]
___:009FA9F5 81 C1 00 00 40 00                       add     ecx, 400000h
___:009FA9FB 89 8D 44 FF FF FF                       mov     [ebp+var_BC], ecx
___:009FAA01 8B 95 68 FF FF FF                       mov     edx, [ebp+var_98]
___:009FAA07 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FAA0D 89 95 68 FF FF FF                       mov     [ebp+var_98], edx
___:009FAA13 8B 85 74 FF FF FF                       mov     eax, [ebp+var_8C]
___:009FAA19 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FAA1E 89 85 74 FF FF FF                       mov     [ebp+var_8C], eax
___:009FAA24 C7 85 4C FF FF FF 45 C7+                mov     [ebp+var_B4], 0DDDDC745h
___:009FAA2E C7 05 80 52 CC 00 00 00+                mov     g_bCallAuth_Maybe, 0
___:009FAA38 8B 8D 34 FF FF FF                       mov     ecx, [ebp+var_CC]
___:009FAA3E 51                                      push    ecx
___:009FAA3F 8D 95 38 FF FF FF                       lea     edx, [ebp+var_C8]
___:009FAA45 52                                      push    edx
___:009FAA46 8B 85 48 FF FF FF                       mov     eax, [ebp+var_B8]
___:009FAA4C 50                                      push    eax
___:009FAA4D 8D 8D 4C FF FF FF                       lea     ecx, [ebp+var_B4]
___:009FAA53 51                                      push    ecx
___:009FAA54 8B 95 74 FF FF FF                       mov     edx, [ebp+var_8C]
___:009FAA5A 52                                      push    edx
___:009FAA5B 8B 85 44 FF FF FF                       mov     eax, [ebp+var_BC]
___:009FAA61 50                                      push    eax
___:009FAA62 E8 89 9F 08 00                          call    Crc32_GetCrc32
___:009FAA67 83 C4 18                                add     esp, 18h
___:009FAA6A 89 85 40 FF FF FF                       mov     [ebp+var_C0], eax
___:009FAA70 83 BD 40 FF FF FF 00                    cmp     [ebp+var_C0], 0
___:009FAA77 74 15                                   jz      short loc_9FAA8E
___:009FAA79 81 BD 4C FF FF FF 10 12+                cmp     [ebp+var_B4], 101210h
___:009FAA83 75 09                                   jnz     short loc_9FAA8E
___:009FAA85 83 3D 80 52 CC 00 01                    cmp     g_bCallAuth_Maybe, 1
___:009FAA8C 74 26                                   jz      short loc_9FAAB4
___:009FAA8E
___:009FAA8E                         loc_9FAA8E:                             ; CODE XREF: CWvsApp__Run+ED7↑j
___:009FAA8E                                                                 ; CWvsApp__Run+EE3↑j
___:009FAA8E 90                                      nop
___:009FAA8F 90                                      nop
___:009FAA90 90                                      nop
___:009FAA91 90                                      nop
___:009FAA92 90                                      nop
___:009FAA93 90                                      nop
___:009FAA94 90                                      nop
___:009FAA95 90                                      nop
___:009FAA96 90                                      nop
___:009FAA97 90                                      nop
___:009FAA98 90                                      nop
___:009FAA99 90                                      nop
___:009FAA9A 90                                      nop
___:009FAA9B 90                                      nop
___:009FAA9C 90                                      nop
___:009FAA9D 90                                      nop
___:009FAA9E 90                                      nop
___:009FAA9F 90                                      nop
___:009FAAA0 90                                      nop
___:009FAAA1 90                                      nop
___:009FAAA2 90                                      nop
___:009FAAA3 90                                      nop
___:009FAAA4 90                                      nop
___:009FAAA5 90                                      nop
___:009FAAA6 90                                      nop
___:009FAAA7 90                                      nop
___:009FAAA8 90                                      nop
___:009FAAA9 90                                      nop
___:009FAAAA 90                                      nop
___:009FAAAB 90                                      nop
___:009FAAAC 90                                      nop
___:009FAAAD 90                                      nop
___:009FAAAE 90                                      nop
___:009FAAAF 90                                      nop
___:009FAAB0 90                                      nop
___:009FAAB1 90                                      nop
___:009FAAB2 90                                      nop
___:009FAAB3 90                                      nop
___:009FAAB4
___:009FAAB4                         loc_9FAAB4:                             ; CODE XREF: CWvsApp__Run+EEC↑j
___:009FAAB4 8B 4D E4                                mov     ecx, [ebp+var_1C]
___:009FAAB7 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FAABD 89 4D E4                                mov     [ebp+var_1C], ecx
___:009FAAC0 8B 55 B0                                mov     edx, [ebp+var_50]
___:009FAAC3 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FAAC9 89 55 B0                                mov     [ebp+var_50], edx
___:009FAACC 8B 85 68 FF FF FF                       mov     eax, [ebp+var_98]
___:009FAAD2 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FAAD7 89 85 68 FF FF FF                       mov     [ebp+var_98], eax
___:009FAADD 8B 8D 74 FF FF FF                       mov     ecx, [ebp+var_8C]
___:009FAAE3 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FAAE9 89 8D 74 FF FF FF                       mov     [ebp+var_8C], ecx
___:009FAAEF 8B 55 DC                                mov     edx, [ebp+var_24]
___:009FAAF2 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FAAF8 89 55 DC                                mov     [ebp+var_24], edx
___:009FAAFB 8B 85 7C FF FF FF                       mov     eax, [ebp+var_84]
___:009FAB01 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FAB06 89 85 7C FF FF FF                       mov     [ebp+var_84], eax
___:009FAB0C 8B 8D 40 FF FF FF                       mov     ecx, [ebp+var_C0]
___:009FAB12 3B 4D E4                                cmp     ecx, [ebp+var_1C]
___:009FAB15 72 0E                                   jb      short loc_9FAB25
___:009FAB17 8B 55 E4                                mov     edx, [ebp+var_1C]
___:009FAB1A 03 55 B0                                add     edx, [ebp+var_50]
___:009FAB1D 39 95 40 FF FF FF                       cmp     [ebp+var_C0], edx
___:009FAB23 72 48                                   jb      short loc_9FAB6D
___:009FAB25
___:009FAB25                         loc_9FAB25:                             ; CODE XREF: CWvsApp__Run+F75↑j
___:009FAB25 8B 85 40 FF FF FF                       mov     eax, [ebp+var_C0]
___:009FAB2B 3B 85 68 FF FF FF                       cmp     eax, [ebp+var_98]
___:009FAB31 72 14                                   jb      short loc_9FAB47
___:009FAB33 8B 8D 68 FF FF FF                       mov     ecx, [ebp+var_98]
___:009FAB39 03 8D 74 FF FF FF                       add     ecx, [ebp+var_8C]
___:009FAB3F 39 8D 40 FF FF FF                       cmp     [ebp+var_C0], ecx
___:009FAB45 72 26                                   jb      short loc_9FAB6D
___:009FAB47
___:009FAB47                         loc_9FAB47:                             ; CODE XREF: CWvsApp__Run+F91↑j
___:009FAB47 90                                      nop
___:009FAB48 90                                      nop
___:009FAB49 90                                      nop
___:009FAB4A 90                                      nop
___:009FAB4B 90                                      nop
___:009FAB4C 90                                      nop
___:009FAB4D 90                                      nop
___:009FAB4E 90                                      nop
___:009FAB4F 90                                      nop
___:009FAB50 90                                      nop
___:009FAB51 90                                      nop
___:009FAB52 90                                      nop
___:009FAB53 90                                      nop
___:009FAB54 90                                      nop
___:009FAB55 90                                      nop
___:009FAB56 90                                      nop
___:009FAB57 90                                      nop
___:009FAB58 90                                      nop
___:009FAB59 90                                      nop
___:009FAB5A 90                                      nop
___:009FAB5B 90                                      nop
___:009FAB5C 90                                      nop
___:009FAB5D 90                                      nop
___:009FAB5E 90                                      nop
___:009FAB5F 90                                      nop
___:009FAB60 90                                      nop
___:009FAB61 90                                      nop
___:009FAB62 90                                      nop
___:009FAB63 90                                      nop
___:009FAB64 90                                      nop
___:009FAB65 90                                      nop
___:009FAB66 90                                      nop
___:009FAB67 90                                      nop
___:009FAB68 90                                      nop
___:009FAB69 90                                      nop
___:009FAB6A 90                                      nop
___:009FAB6B 90                                      nop
___:009FAB6C 90                                      nop
___:009FAB6D
___:009FAB6D                         loc_9FAB6D:                             ; CODE XREF: CWvsApp__Run+F83↑j
___:009FAB6D                                                                 ; CWvsApp__Run+FA5↑j
___:009FAB6D 8B 55 E4                                mov     edx, [ebp+var_1C]
___:009FAB70 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FAB76 89 55 E4                                mov     [ebp+var_1C], edx
___:009FAB79 8B 45 B0                                mov     eax, [ebp+var_50]
___:009FAB7C 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FAB81 89 45 B0                                mov     [ebp+var_50], eax
___:009FAB84 8B 8D 68 FF FF FF                       mov     ecx, [ebp+var_98]
___:009FAB8A 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FAB90 89 8D 68 FF FF FF                       mov     [ebp+var_98], ecx
___:009FAB96 8B 95 74 FF FF FF                       mov     edx, [ebp+var_8C]
___:009FAB9C 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FABA2 89 95 74 FF FF FF                       mov     [ebp+var_8C], edx
___:009FABA8 8B 45 DC                                mov     eax, [ebp+var_24]
___:009FABAB 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FABB0 89 45 DC                                mov     [ebp+var_24], eax
___:009FABB3 8B 8D 7C FF FF FF                       mov     ecx, [ebp+var_84]
___:009FABB9 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FABBF 89 8D 7C FF FF FF                       mov     [ebp+var_84], ecx
___:009FABC5 8B 95 74 FF FF FF                       mov     edx, [ebp+var_8C]
___:009FABCB 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FABD1 89 95 74 FF FF FF                       mov     [ebp+var_8C], edx
___:009FABD7 8B 85 7C FF FF FF                       mov     eax, [ebp+var_84]
___:009FABDD 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FABE2 89 85 7C FF FF FF                       mov     [ebp+var_84], eax
___:009FABE8 8B 8D 38 FF FF FF                       mov     ecx, [ebp+var_C8]
___:009FABEE 81 F1 90 11 52 81                       xor     ecx, 81521190h
___:009FABF4 89 8D 38 FF FF FF                       mov     [ebp+var_C8], ecx
___:009FABFA 8B 95 7C FF FF FF                       mov     edx, [ebp+var_84]
___:009FAC00 3B 95 38 FF FF FF                       cmp     edx, [ebp+var_C8]
___:009FAC06 74 26                                   jz      short loc_9FAC2E
___:009FAC08 90                                      nop
___:009FAC09 90                                      nop
___:009FAC0A 90                                      nop
___:009FAC0B 90                                      nop
___:009FAC0C 90                                      nop
___:009FAC0D 90                                      nop
___:009FAC0E 90                                      nop
___:009FAC0F 90                                      nop
___:009FAC10 90                                      nop
___:009FAC11 90                                      nop
___:009FAC12 90                                      nop
___:009FAC13 90                                      nop
___:009FAC14 90                                      nop
___:009FAC15 90                                      nop
___:009FAC16 90                                      nop
___:009FAC17 90                                      nop
___:009FAC18 90                                      nop
___:009FAC19 90                                      nop
___:009FAC1A 90                                      nop
___:009FAC1B 90                                      nop
___:009FAC1C 90                                      nop
___:009FAC1D 90                                      nop
___:009FAC1E 90                                      nop
___:009FAC1F 90                                      nop
___:009FAC20 90                                      nop
___:009FAC21 90                                      nop
___:009FAC22 90                                      nop
___:009FAC23 90                                      nop
___:009FAC24 90                                      nop
___:009FAC25 90                                      nop
___:009FAC26 90                                      nop
___:009FAC27 90                                      nop
___:009FAC28 90                                      nop
___:009FAC29 90                                      nop
___:009FAC2A 90                                      nop
___:009FAC2B 90                                      nop
___:009FAC2C 90                                      nop
___:009FAC2D 90                                      nop
___:009FAC2E
___:009FAC2E                         loc_9FAC2E:                             ; CODE XREF: CWvsApp__Run+1066↑j
___:009FAC2E 8B 85 7C FF FF FF                       mov     eax, [ebp+var_84]
___:009FAC34 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FAC39 89 85 7C FF FF FF                       mov     [ebp+var_84], eax
___:009FAC3F
___:009FAC3F                         loc_9FAC3F:                             ; CODE XREF: CWvsApp__Run+E1A↑j
___:009FAC3F 83 7D E0 01                             cmp     [ebp+var_20], 1
___:009FAC43 0F 85 0E 02 00 00                       jnz     loc_9FAE57
___:009FAC49 C7 85 14 FF FF FF 00 00+                mov     [ebp+var_EC], 0
___:009FAC53 C7 85 08 FF FF FF 00 00+                mov     [ebp+var_F8], 0
___:009FAC5D C7 85 18 FF FF FF 00 00+                mov     [ebp+var_E8], 0
___:009FAC67 C7 85 0C FF FF FF 00 00+                mov     [ebp+var_F4], 0
___:009FAC71 C7 85 1C FF FF FF 00 00+                mov     [ebp+var_E4], 0
___:009FAC7B C7 85 10 FF FF FF 00 00+                mov     [ebp+var_F0], 0
___:009FAC85 C7 85 04 FF FF FF 00 00+                mov     [ebp+var_FC], 0
___:009FAC8F C7 85 14 FF FF FF 53 89+                mov     [ebp+var_EC], 0CA218953h
___:009FAC99 C7 85 08 FF FF FF 6C 58+                mov     [ebp+var_F8], 395A586Ch
___:009FACA3 C7 85 18 FF FF FF 05 00+                mov     [ebp+var_E8], 5
___:009FACAD 8B 8D 60 FF FF FF                       mov     ecx, [ebp+var_A0]
___:009FACB3 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FACB9 89 8D 60 FF FF FF                       mov     [ebp+var_A0], ecx
___:009FACBF 8B 95 18 FF FF FF                       mov     edx, [ebp+var_E8]
___:009FACC5 8B 45 90                                mov     eax, [ebp+lpMem]
___:009FACC8 8B 0C 90                                mov     ecx, [eax+edx*4]
___:009FACCB 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FACD1 81 E9 00 00 00 20                       sub     ecx, 20000000h
___:009FACD7 89 8D 0C FF FF FF                       mov     [ebp+var_F4], ecx
___:009FACDD 8B 95 18 FF FF FF                       mov     edx, [ebp+var_E8]
___:009FACE3 8B 45 90                                mov     eax, [ebp+lpMem]
___:009FACE6 8D 0C 90                                lea     ecx, [eax+edx*4]
___:009FACE9 8B 95 60 FF FF FF                       mov     edx, [ebp+var_A0]
___:009FACEF 83 EA 01                                sub     edx, 1
___:009FACF2 6B D2 03                                imul    edx, 3
___:009FACF5 8B 04 91                                mov     eax, [ecx+edx*4]
___:009FACF8 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FACFD 2D 00 00 00 20                          sub     eax, 20000000h
___:009FAD02 2B 85 0C FF FF FF                       sub     eax, [ebp+var_F4]
___:009FAD08 89 85 1C FF FF FF                       mov     [ebp+var_E4], eax
___:009FAD0E 8B 8D 18 FF FF FF                       mov     ecx, [ebp+var_E8]
___:009FAD14 8B 55 90                                mov     edx, [ebp+lpMem]
___:009FAD17 8D 04 8A                                lea     eax, [edx+ecx*4]
___:009FAD1A 8B 8D 60 FF FF FF                       mov     ecx, [ebp+var_A0]
___:009FAD20 83 E9 01                                sub     ecx, 1
___:009FAD23 6B C9 03                                imul    ecx, 3
___:009FAD26 8B 54 88 04                             mov     edx, [eax+ecx*4+4]
___:009FAD2A 81 F2 8F AE C9 37                       xor     edx, 37C9AE8Fh
___:009FAD30 03 95 1C FF FF FF                       add     edx, [ebp+var_E4]
___:009FAD36 89 95 1C FF FF FF                       mov     [ebp+var_E4], edx
___:009FAD3C C7 85 10 FF FF FF FF FF+                mov     [ebp+var_F0], 0FFFFFFFFh
___:009FAD46 C7 85 4C FF FF FF BC AD+                mov     [ebp+var_B4], 28ADBCh
___:009FAD50 8B 85 08 FF FF FF                       mov     eax, [ebp+var_F8]
___:009FAD56 50                                      push    eax
___:009FAD57 8D 8D 10 FF FF FF                       lea     ecx, [ebp+var_F0]
___:009FAD5D 51                                      push    ecx
___:009FAD5E 8B 95 14 FF FF FF                       mov     edx, [ebp+var_EC]
___:009FAD64 52                                      push    edx
___:009FAD65 8D 85 4C FF FF FF                       lea     eax, [ebp+var_B4]
___:009FAD6B 50                                      push    eax
___:009FAD6C 8B 8D 1C FF FF FF                       mov     ecx, [ebp+var_E4]
___:009FAD72 51                                      push    ecx
___:009FAD73 8B 95 0C FF FF FF                       mov     edx, [ebp+var_F4]
___:009FAD79 52                                      push    edx
___:009FAD7A E8 61 A6 08 00                          call    Crc32__GetCrc32_VMCRC
___:009FAD7F 83 C4 18                                add     esp, 18h
___:009FAD82 85 C0                                   test    eax, eax
___:009FAD84 74 0C                                   jz      short loc_9FAD92
___:009FAD86 81 BD 4C FF FF FF 10 12+                cmp     [ebp+var_B4], 101210h
___:009FAD90 74 30                                   jz      short loc_9FADC2
___:009FAD92
___:009FAD92                         loc_9FAD92:                             ; CODE XREF: CWvsApp__Run+11E4↑j
___:009FAD92 C7 85 60 FF FF FF 00 00+                mov     [ebp+var_A0], 0
___:009FAD9C 90                                      nop
___:009FAD9D 90                                      nop
___:009FAD9E 90                                      nop
___:009FAD9F 90                                      nop
___:009FADA0 90                                      nop
___:009FADA1 90                                      nop
___:009FADA2 90                                      nop
___:009FADA3 90                                      nop
___:009FADA4 90                                      nop
___:009FADA5 90                                      nop
___:009FADA6 90                                      nop
___:009FADA7 90                                      nop
___:009FADA8 90                                      nop
___:009FADA9 90                                      nop
___:009FADAA 90                                      nop
___:009FADAB 90                                      nop
___:009FADAC 90                                      nop
___:009FADAD 90                                      nop
___:009FADAE 90                                      nop
___:009FADAF 90                                      nop
___:009FADB0 90                                      nop
___:009FADB1 90                                      nop
___:009FADB2 90                                      nop
___:009FADB3 90                                      nop
___:009FADB4 90                                      nop
___:009FADB5 90                                      nop
___:009FADB6 90                                      nop
___:009FADB7 90                                      nop
___:009FADB8 90                                      nop
___:009FADB9 90                                      nop
___:009FADBA 90                                      nop
___:009FADBB 90                                      nop
___:009FADBC 90                                      nop
___:009FADBD 90                                      nop
___:009FADBE 90                                      nop
___:009FADBF 90                                      nop
___:009FADC0 90                                      nop
___:009FADC1 90                                      nop
___:009FADC2
___:009FADC2                         loc_9FADC2:                             ; CODE XREF: CWvsApp__Run+11F0↑j
___:009FADC2 8B 45 90                                mov     eax, [ebp+lpMem]
___:009FADC5 8B 08                                   mov     ecx, [eax]
___:009FADC7 89 8D 04 FF FF FF                       mov     [ebp+var_FC], ecx
___:009FADCD 8B 95 10 FF FF FF                       mov     edx, [ebp+var_F0]
___:009FADD3 3B 95 04 FF FF FF                       cmp     edx, [ebp+var_FC]
___:009FADD9 74 30                                   jz      short loc_9FAE0B
___:009FADDB C7 85 60 FF FF FF 00 00+                mov     [ebp+var_A0], 0
___:009FADE5 90                                      nop
___:009FADE6 90                                      nop
___:009FADE7 90                                      nop
___:009FADE8 90                                      nop
___:009FADE9 90                                      nop
___:009FADEA 90                                      nop
___:009FADEB 90                                      nop
___:009FADEC 90                                      nop
___:009FADED 90                                      nop
___:009FADEE 90                                      nop
___:009FADEF 90                                      nop
___:009FADF0 90                                      nop
___:009FADF1 90                                      nop
___:009FADF2 90                                      nop
___:009FADF3 90                                      nop
___:009FADF4 90                                      nop
___:009FADF5 90                                      nop
___:009FADF6 90                                      nop
___:009FADF7 90                                      nop
___:009FADF8 90                                      nop
___:009FADF9 90                                      nop
___:009FADFA 90                                      nop
___:009FADFB 90                                      nop
___:009FADFC 90                                      nop
___:009FADFD 90                                      nop
___:009FADFE 90                                      nop
___:009FADFF 90                                      nop
___:009FAE00 90                                      nop
___:009FAE01 90                                      nop
___:009FAE02 90                                      nop
___:009FAE03 90                                      nop
___:009FAE04 90                                      nop
___:009FAE05 90                                      nop
___:009FAE06 90                                      nop
___:009FAE07 90                                      nop
___:009FAE08 90                                      nop
___:009FAE09 90                                      nop
___:009FAE0A 90                                      nop
___:009FAE0B
___:009FAE0B                         loc_9FAE0B:                             ; CODE XREF: CWvsApp__Run+1239↑j
___:009FAE0B C7 85 4C FF FF FF 00 00+                mov     [ebp+var_B4], 0
___:009FAE15 8B 85 4C FF FF FF                       mov     eax, [ebp+var_B4]
___:009FAE1B 89 85 04 FF FF FF                       mov     [ebp+var_FC], eax
___:009FAE21 8B 8D 04 FF FF FF                       mov     ecx, [ebp+var_FC]
___:009FAE27 89 8D 10 FF FF FF                       mov     [ebp+var_F0], ecx
___:009FAE2D 8B 95 10 FF FF FF                       mov     edx, [ebp+var_F0]
___:009FAE33 89 95 1C FF FF FF                       mov     [ebp+var_E4], edx
___:009FAE39 8B 85 1C FF FF FF                       mov     eax, [ebp+var_E4]
___:009FAE3F 89 85 0C FF FF FF                       mov     [ebp+var_F4], eax
___:009FAE45 8B 8D 60 FF FF FF                       mov     ecx, [ebp+var_A0]
___:009FAE4B 81 F1 8F AE C9 37                       xor     ecx, 37C9AE8Fh
___:009FAE51 89 8D 60 FF FF FF                       mov     [ebp+var_A0], ecx
___:009FAE57
___:009FAE57                         loc_9FAE57:                             ; CODE XREF: CWvsApp__Run+10A3↑j
___:009FAE57 8B 55 E0                                mov     edx, [ebp+var_20]
___:009FAE5A 83 C2 01                                add     edx, 1
___:009FAE5D 89 55 E0                                mov     [ebp+var_20], edx
___:009FAE60 8B 45 E0                                mov     eax, [ebp+var_20]
___:009FAE63 35 8F AE C9 37                          xor     eax, 37C9AE8Fh
___:009FAE68 89 45 E0                                mov     [ebp+var_20], eax
___:009FAE6B
___:009FAE6B                         loc_9FAE6B:                             ; CODE XREF: CWvsApp__Run+B36↑j
___:009FAE6B 8B 8D A4 F2 FF FF                       mov     ecx, [ebp+var_D5C]
___:009FAE71 8B 95 54 FF FF FF                       mov     edx, [ebp+var_AC]
___:009FAE77 2B 51 5C                                sub     edx, [ecx+5Ch]
___:009FAE7A 8B 85 50 FF FF FF                       mov     eax, [ebp+var_B0]
___:009FAE80 6B C0 3C                                imul    eax, 3Ch
___:009FAE83 69 C0 E8 03 00 00                       imul    eax, 3E8h
___:009FAE89 39 C2                                   cmp     edx, eax
___:009FAE8B 0F 8E 96 04 00 00                       jle     loc_9FB327
___:009FAE91 8B 8D A4 F2 FF FF                       mov     ecx, [ebp+var_D5C]
___:009FAE97 8B 95 54 FF FF FF                       mov     edx, [ebp+var_AC]
___:009FAE9D 89 51 5C                                mov     [ecx+5Ch], edx
___:009FAEA0 83 3D 98 F1 CB 00 00                    cmp     dword_CBF198, 0
___:009FAEA7 0F 85 AA 01 00 00                       jnz     loc_9FB057
___:009FAEAD C6 85 58 FD FF FF 5C                    mov     [ebp+ModuleName], 5Ch
___:009FAEB4 C6 85 59 FD FF FF 5C                    mov     [ebp+var_2A7], 5Ch
___:009FAEBB C6 85 5A FD FF FF 77                    mov     [ebp+var_2A6], 77h
___:009FAEC2 C6 85 5B FD FF FF 73                    mov     [ebp+var_2A5], 73h
___:009FAEC9 C6 85 5C FD FF FF 32                    mov     [ebp+var_2A4], 32h
___:009FAED0 C6 85 5D FD FF FF 5F                    mov     [ebp+var_2A3], 5Fh
___:009FAED7 C6 85 5E FD FF FF 33                    mov     [ebp+var_2A2], 33h
___:009FAEDE C6 85 5F FD FF FF 32                    mov     [ebp+var_2A1], 32h
___:009FAEE5 C6 85 60 FD FF FF 2E                    mov     [ebp+var_2A0], 2Eh
___:009FAEEC C6 85 61 FD FF FF 64                    mov     [ebp+var_29F], 64h
___:009FAEF3 C6 85 62 FD FF FF 6C                    mov     [ebp+var_29E], 6Ch
___:009FAEFA C6 85 63 FD FF FF 6C                    mov     [ebp+var_29D], 6Ch
___:009FAF01 C6 85 64 FD FF FF 00                    mov     [ebp+var_29C], 0
___:009FAF08 8D 85 58 FD FF FF                       lea     eax, [ebp+ModuleName]
___:009FAF0E 50                                      push    eax             ; lpModuleName
___:009FAF0F FF 15 4C 51 B5 00                       call    GetModuleHandleA
___:009FAF15 89 85 44 FD FF FF                       mov     [ebp+hModule], eax
___:009FAF1B E8 20 3B A6 FF                          call    sub_45EA40
___:009FAF20 89 85 68 FD FF FF                       mov     [ebp+var_298], eax
___:009FAF26 83 BD 68 FD FF FF 00                    cmp     [ebp+var_298], 0
___:009FAF2D 75 26                                   jnz     short loc_9FAF55
___:009FAF2F 90                                      nop
___:009FAF30 90                                      nop
___:009FAF31 90                                      nop
___:009FAF32 90                                      nop
___:009FAF33 90                                      nop
___:009FAF34 90                                      nop
___:009FAF35 90                                      nop
___:009FAF36 90                                      nop
___:009FAF37 90                                      nop
___:009FAF38 90                                      nop
___:009FAF39 90                                      nop
___:009FAF3A 90                                      nop
___:009FAF3B 90                                      nop
___:009FAF3C 90                                      nop
___:009FAF3D 90                                      nop
___:009FAF3E 90                                      nop
___:009FAF3F 90                                      nop
___:009FAF40 90                                      nop
___:009FAF41 90                                      nop
___:009FAF42 90                                      nop
___:009FAF43 90                                      nop
___:009FAF44 90                                      nop
___:009FAF45 90                                      nop
___:009FAF46 90                                      nop
___:009FAF47 90                                      nop
___:009FAF48 90                                      nop
___:009FAF49 90                                      nop
___:009FAF4A 90                                      nop
___:009FAF4B 90                                      nop
___:009FAF4C 90                                      nop
___:009FAF4D 90                                      nop
___:009FAF4E 90                                      nop
___:009FAF4F 90                                      nop
___:009FAF50 90                                      nop
___:009FAF51 90                                      nop
___:009FAF52 90                                      nop
___:009FAF53 90                                      nop
___:009FAF54 90                                      nop
___:009FAF55
```

## MapleStory CRC Checks ( MSCRC )

#### Please contribute to this section if you have anything to add!!!

### Crc32__GetCrc32_VMCRC
Called in tSecurityCheck
A CRC of MapleStory's memory regions to check for memory edits
You cannot simply swap the params to a clean copy of the memory, you need to hook and swap in the middle ( after the if statements ) 


Pseudo:
```
unsigned int __cdecl Crc32_GetCrc32_VMCRC(unsigned int *pmem, unsigned int size, unsigned int *pcheck, unsigned int base1, unsigned int *pCrc32, unsigned int base2)
{
  struct _TEB *v6; // eax
  _DWORD *v7; // ecx
  _DWORD *n; // eax
  unsigned int result; // eax
  _IMAGE_NT_HEADERS *pNtHdrs; // ST4C_4
  struct _TEB *v11; // eax
  _DWORD *v12; // ecx
  _DWORD *m; // eax
  struct _TEB *v14; // eax
  _DWORD *v15; // ecx
  _DWORD *j; // eax
  struct _TEB *v17; // eax
  _DWORD *v18; // ecx
  _DWORD *k; // eax
  struct _TEB *v20; // eax
  _DWORD *v21; // ecx
  _DWORD *l; // eax
  unsigned int i; // [esp+8h] [ebp-3Ch]
  int bLoopAuth; // [esp+Ch] [ebp-38h]
  unsigned int crc32; // [esp+18h] [ebp-2Ch]
  unsigned int checkSize; // [esp+20h] [ebp-24h]
  int checkSizea; // [esp+20h] [ebp-24h]
  int checkSizeb; // [esp+20h] [ebp-24h]
  unsigned int vm; // [esp+24h] [ebp-20h]
  unsigned int checkAddr; // [esp+2Ch] [ebp-18h]
  int checkAddra; // [esp+2Ch] [ebp-18h]
  unsigned int checkAddrb; // [esp+2Ch] [ebp-18h]

  GetTickCount();
  if ( (base1 ^ 0xCA618953) == (base2 ^ 0x391A586C) )
  {
    pNtHdrs = (_IMAGE_NT_HEADERS *)(*(_DWORD *)((base1 ^ 0xCA618953) + 0x3C) + (base1 ^ 0xCA618953));
    checkAddr = pNtHdrs->OptionalHeader.ImageBase
              + ((*(&pNtHdrs[1].FileHeader.PointerToSymbolTable + 10 * pNtHdrs->FileHeader.NumberOfSections)
                - (*(&pNtHdrs[1].FileHeader.NumberOfSymbols + 10 * (pNtHdrs->FileHeader.NumberOfSections - 1))
                 + *(&pNtHdrs[1].FileHeader.PointerToSymbolTable + 10 * (pNtHdrs->FileHeader.NumberOfSections - 1)))) ^ 0x23126032);
    checkSize = pNtHdrs->OptionalHeader.SizeOfImage;
    if ( (unsigned int)pmem >= checkAddr && (unsigned int)pmem < checkSize + checkAddr )
    {
      checkAddra = checkAddr ^ 0x37C9AE8F;
      checkSizea = checkSize ^ 0x37C9AE8F;
      bLoopAuth = 0;
      if ( *pCrc32 == -1 )
        *pCrc32 = -2125327984;
      crc32 = *pCrc32;
      vm = size >> 3;
      for ( i = 0; i < size >> 2; ++i )
      {
        if ( i == vm )
        {
          if ( (base1 ^ 0xCA618953) != (base2 ^ 0x391A586C) )
          {
            v14 = NtCurrentTeb();
            v15 = v14->NtTib.StackLimit;
            for ( j = v14->NtTib.StackBase; j > v15; *j = 0 )
              --j;
            return 0;
          }
          checkAddrb = checkAddra ^ 0x37C9AE8F;
          checkSizeb = checkSizea ^ 0x37C9AE8F;
          if ( (unsigned int)pmem < checkAddrb || (unsigned int)pmem >= checkSizeb + checkAddrb )
          {
            v17 = NtCurrentTeb();
            v18 = v17->NtTib.StackLimit;
            for ( k = v17->NtTib.StackBase; k > v18; *k = 0 )
              --k;
            return 0;
          }
          checkSizea = 0;
          checkAddra = 0;
          bLoopAuth = 1;
          *pCrc32 = ((i ^ 0x1012) + g_crc32Table[(pmem[i] ^ *pCrc32) & 0xFF]) ^ (*pCrc32 >> 8);
          vm = i == 0 ? i : 0;
          *pcheck = vm * *pcheck + 0x101210;
          crc32 = *pCrc32 + 1;
        }
        else
        {
          *pCrc32 = g_crc32Table[(pmem[i] ^ *pCrc32) & 0xFF] ^ (*pCrc32 >> 8);
        }
      }
      if ( bLoopAuth )
      {
        GetTickCount();
        result = crc32;
      }
      else
      {
        v20 = NtCurrentTeb();
        v21 = v20->NtTib.StackLimit;
        for ( l = v20->NtTib.StackBase; l > v21; *l = 0 )
          --l;
        result = 0;
      }
    }
    else
    {
      v11 = NtCurrentTeb();
      v12 = v11->NtTib.StackLimit;
      for ( m = v11->NtTib.StackBase; m > v12; *m = 0 )
        --m;
      result = 0;
    }
  }
  else
  {
    v6 = NtCurrentTeb();
    v7 = v6->NtTib.StackLimit;
    for ( n = v6->NtTib.StackBase; n > v7; *n = 0 )
      --n;
    result = 0;
  }
  return result;
}

```

### Crc32__GetCrc32_VMTABLE
Called regularly in CWvsApp::Run
A CRC check against themidas VMTABLE I believe. With that being said im pretty sure if you leave binary as is and do not unpack this'll execute fine ( it does right now )

Pseudo:
```
unsigned int __cdecl Crc32_GetCrc32_VMTable(unsigned int *pmem, unsigned int size, unsigned int *pcheck, unsigned int *pCrc32)
{
  struct _TEB *v4; // eax
  _DWORD *v5; // ecx
  _DWORD *j; // eax
  unsigned int result; // eax
  unsigned int i; // [esp+0h] [ebp-1Ch]
  int bLoopAuth; // [esp+4h] [ebp-18h]
  unsigned int crc32; // [esp+8h] [ebp-14h]
  unsigned int vm; // [esp+10h] [ebp-Ch]

  GetTickCount();
  bLoopAuth = 0;
  if ( *pCrc32 == -1 )
    *pCrc32 = 0x81521190;
  crc32 = *pCrc32;
  vm = size >> 3;
  for ( i = 0; i < size >> 2; ++i )
  {
    if ( i == vm )
    {
      bLoopAuth = 1;
      *pCrc32 = ((i ^ 0x1012) + g_crc32Table[(pmem[i] ^ *pCrc32) & 0xFF]) ^ (*pCrc32 >> 8);
      vm = i == 0 ? i : 0;
      *pcheck = vm * *pcheck + 1053200;
      crc32 = *pCrc32 + 1;
    }
    else
    {
      *pCrc32 = g_crc32Table[(pmem[i] ^ *pCrc32) & 0xFF] ^ (*pCrc32 >> 8);
    }
  }
  if ( bLoopAuth )
  {
    GetTickCount();
    result = crc32;
  }
  else
  {
    v4 = NtCurrentTeb();
    v5 = v4->NtTib.StackLimit;
    for ( j = v4->NtTib.StackBase; j > v5; *j = 0 )
      --j;
    result = 0;
  }
  return result;
}
```


## CWvsContext::OnEnterField
Ignore this super shitty pseudo analysis below until I actually solve it. PatchRetZero to skip the call. 
This MSCRC bypass still used in v200 GMS today. However it skips some game code we need actually need !!! ( Closing UI's and other things )

```
//Three VM sections in here
void CWvsContext::OnEnterField()
{
//BlaBlaBla

CWvsContext::UI_CloseRevive()

BEGIN_VM_BLOCK

bAuth is a parameter/ret in a MSCRC function (?)

bAuth = 0
var24 = 0
var28 = CClientSocket::SendPacket

SEND_PACKET_CHECK

//This mov may have been insert manually
_text:009DBF79 058 C7 45 E8 15 08 45 19                          mov     [ebp+dwThemidaCheckValue], 19450815h

NOPPED CODE I BELIEVE TO THE MSCRC

Compare ebp_dwThemidaCheckValue to the hardcoded value

If check fails: CLIENT_BLOWUP_DEATH

END_VM_BLOCK

CTemporaryStatView::Show(void)
//BlaBlaBla
TSingleton<CRadioManager>::GetInstance(void)

BEGIN_VM_BLOCK
Nopped Shit I need to RE
END_VM_BLOCK

TSingleton<CUIStatusBar>::IsInstantiated(void)
//BlaBlaBla
CField::IsSwimmingMap()

BEGIN_VM_BLOCK
Check value of ` bAuth `
If check fails: CLIENT_BLOWUP_DEATH
END_VM_BLOCK


CTemporaryStatView::Show(void)
//BlaBlaBla
CConfig::SaveSessionInfo_FieldID()
}
```

## Macros / Methods
These are self defined btw

### CHECK_SEND_PACKET
```
Check first byte of CClientSocket::SendPacket against:
(0x55 or 0xB8 or 0x6A )
```

### CLIENT_BLOWUP_DEATH
Ignore the address' as it's just IDA copy paste for pseudo
```
_text:009DBF53 058 31 DB                                         xor     ebx, ebx
_text:009DBF55 058 31 D2                                         xor     edx, edx
_text:009DBF57 058 31 F6                                         xor     esi, esi
_text:009DBF59 058 31 FF                                         xor     edi, edi
_text:009DBF5B 058 31 ED                                         xor     ebp, ebp
_text:009DBF5D 058 64 A1 18 00 00 00                             mov     eax, large fs:18h
_text:009DBF63 058 8B 48 08                                      mov     ecx, [eax+8]
_text:009DBF66 058 8B 40 04                                      mov     eax, [eax+4]
_text:009DBF69
_text:009DBF69                                   loc_9DBF69:                             ; CODE XREF: CWvsContext::OnEnterField(void)+B2↓j
_text:009DBF69 058 39 C8                                         cmp     eax, ecx
_text:009DBF6B 058 76 07                                         jbe     short loc_9DBF74
_text:009DBF6D 058 83 E8 04                                      sub     eax, 4
_text:009DBF70 058 89 18                                         mov     [eax], ebx
_text:009DBF72 058 EB F5                                         jmp     short loc_9DBF69
```

## Other Checks

  - Game checks ` ws2_32.dll ` dos header magic to see if its been tampered
  - Game removes loopback adapters ` ResetLSP() `
  - ` GetIpAddrTable GetAdaptersInfo ` calls used to check adapter stuff ?
  - Client ` OpenMutexA ` for the HackShield mutex ` meteora `
  - Client checks to see if ` ehsvc.dll ` is loaded
  - Client literally does an IAT count on the ` ehsvc.dll ` to see if its been tampered. I just loaded original
  - Client ` CreateMutexA ` for multi client mutex ` WvsClientMutex ` mutex

## Other Functions

#### DR_check
This function checks for the debug register. PatchRetZero

#### HideDll
This function removes the module from the module list.  This crashes on anything higher than Win7. PatchRetZero
```cpp
void __cdecl HideDll(HINSTANCE__ *hModule)
{
  _LDR_MODULE *pLdrModule; // [esp+0h] [ebp-8h]

  for ( pLdrModule = (_LDR_MODULE *)NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList.Flink;
        pLdrModule->BaseAddress && pLdrModule->BaseAddress != hModule;
        pLdrModule = (_LDR_MODULE *)pLdrModule->InLoadOrderModuleList.Flink )
  {
    ;
  }
  if ( pLdrModule->BaseAddress )
  {
    pLdrModule->InLoadOrderModuleList.Blink->Flink = pLdrModule->InLoadOrderModuleList.Flink;
    pLdrModule->InLoadOrderModuleList.Flink->Blink = pLdrModule->InLoadOrderModuleList.Blink;
    pLdrModule->InMemoryOrderModuleList.Blink->Flink = pLdrModule->InMemoryOrderModuleList.Flink;
    pLdrModule->InMemoryOrderModuleList.Flink->Blink = pLdrModule->InMemoryOrderModuleList.Blink;
    pLdrModule->InInitializationOrderModuleList.Blink->Flink = pLdrModule->InInitializationOrderModuleList.Flink;
    pLdrModule->InInitializationOrderModuleList.Flink->Blink = pLdrModule->InInitializationOrderModuleList.Blink;
    pLdrModule->HashTableEntry.Blink->Flink = pLdrModule->HashTableEntry.Flink;
    pLdrModule->HashTableEntry.Flink->Blink = pLdrModule->HashTableEntry.Blink;
    memset(pLdrModule, 0, 0x48u);
  }
}
```

#### SendHSLog
Self explanatory. Called in WinMain. PatchRetZero
```cpp
void __cdecl SendHSLog(unsigned int dwErrCode)
{
  ZXString<char> *v1; // eax
  ZXString<char> result; // [esp+0h] [ebp-314h]
  char szPath[260]; // [esp+4h] [ebp-310h]
  char szHShieldPath[260]; // [esp+108h] [ebp-20Ch]
  char szCharacterName[260]; // [esp+20Ch] [ebp-108h]

  szPath[0] = 0;
  memset(&szPath[1], 0, 0x103u);
  szHShieldPath[0] = 0;
  memset(&szHShieldPath[1], 0, 0x103u);
  szCharacterName[0] = 0;
  memset(&szCharacterName[1], 0, 0x103u);
  GetModuleFileNameA(0, szPath, 0x104u);
  _mbsrchr((const unsigned __int8 *)szPath, 0x5Cu)[1] = 0;
  sprintf(szHShieldPath, "%s\\HShield", szPath);
  v1 = CConfig::GetSessionCharacterName((CConfig *)TSingleton<CConfig>::ms_pInstance._m_pStr, &result);
  sprintf(szCharacterName, "MapleStory_Global:%s", v1->_m_pStr);
  if ( result._m_pStr )
    ZXString<char>::_Release((ZXString<char>::_ZXStringData *)result._m_pStr - 1);
  _AhnHS_SendHsLogA(dwErrCode, (int)szCharacterName, (int)szHShieldPath);
}
```

#### CeTracer::Run
This function sends client crash reports. It makes some reporting window pop up. PatchRetZero
```cpp
void __thiscall CeTracer::Run(CeTracer *this)
{
  if ( this->ET_ErrorCode )
    Start_eTracer(this->ET_ErrorCode, this->ET_MaxErrorCnt);
}
```

## To Do
  - Explain the order of operations / sequence of events
  - ` ZApiLoader `
  - Login IP dynamic initializer `ZInetAddr`
  - MSLoop_Remove();
  - CWvsApp::ConnectLogin(thisa, v5);
  - InitSafeDll_iphdll();
