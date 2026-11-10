; Explorer integration, for the current user only (no administrator rights needed):
;   - "Encrypt with Topal Encryption" on every file and folder
;   - "Decrypt with Topal Encryption" on folders
;   - .topal files get the app's icon, and opening one starts decryption
; Everything written here is removed again by the uninstaller.

!macro NSIS_HOOK_POSTINSTALL
  WriteRegStr HKCU "Software\Classes\*\shell\TopalEncryption.Encrypt" "" "Encrypt with Topal Encryption"
  WriteRegStr HKCU "Software\Classes\*\shell\TopalEncryption.Encrypt" "Icon" "$INSTDIR\TopalEncryption.exe,0"
  WriteRegStr HKCU "Software\Classes\*\shell\TopalEncryption.Encrypt\command" "" '"$INSTDIR\TopalEncryption.exe" --encrypt "%1"'

  WriteRegStr HKCU "Software\Classes\Directory\shell\TopalEncryption.Encrypt" "" "Encrypt with Topal Encryption"
  WriteRegStr HKCU "Software\Classes\Directory\shell\TopalEncryption.Encrypt" "Icon" "$INSTDIR\TopalEncryption.exe,0"
  WriteRegStr HKCU "Software\Classes\Directory\shell\TopalEncryption.Encrypt\command" "" '"$INSTDIR\TopalEncryption.exe" --encrypt "%1"'

  WriteRegStr HKCU "Software\Classes\Directory\shell\TopalEncryption.Decrypt" "" "Decrypt with Topal Encryption"
  WriteRegStr HKCU "Software\Classes\Directory\shell\TopalEncryption.Decrypt" "Icon" "$INSTDIR\TopalEncryption.exe,0"
  WriteRegStr HKCU "Software\Classes\Directory\shell\TopalEncryption.Decrypt\command" "" '"$INSTDIR\TopalEncryption.exe" --decrypt "%1"'

  WriteRegStr HKCU "Software\Classes\.topal" "" "TopalEncryption.File"
  WriteRegStr HKCU "Software\Classes\TopalEncryption.File" "" "Topal Encryption file"
  WriteRegStr HKCU "Software\Classes\TopalEncryption.File\DefaultIcon" "" "$INSTDIR\TopalEncryption.exe,0"
  WriteRegStr HKCU "Software\Classes\TopalEncryption.File\shell\open" "" "Decrypt with Topal Encryption"
  WriteRegStr HKCU "Software\Classes\TopalEncryption.File\shell\open\command" "" '"$INSTDIR\TopalEncryption.exe" --decrypt "%1"'

  ; Tell Explorer that file associations changed (SHCNE_ASSOCCHANGED).
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKCU "Software\Classes\*\shell\TopalEncryption.Encrypt"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\TopalEncryption.Encrypt"
  DeleteRegKey HKCU "Software\Classes\Directory\shell\TopalEncryption.Decrypt"
  DeleteRegKey HKCU "Software\Classes\TopalEncryption.File"
  ; Only if it still points at us: another program may have taken the extension over.
  ReadRegStr $0 HKCU "Software\Classes\.topal" ""
  StrCmp $0 "TopalEncryption.File" 0 +2
  DeleteRegKey HKCU "Software\Classes\.topal"
  System::Call 'shell32::SHChangeNotify(i 0x08000000, i 0, p 0, p 0)'
!macroend
