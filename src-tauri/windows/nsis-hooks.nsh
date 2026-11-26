; Stops the app and its worker so their files can be replaced or removed.
; taskkill fails when a process is not running; that exit code is ignored.

!macro CONDUIT_STOP_PROCESS PROCESS_NAME
  Push $0
  nsExec::ExecToLog 'taskkill /F /IM ${PROCESS_NAME}'
  Pop $0 ; discard the taskkill exit code
  Pop $0 ; restore the caller's $0
!macroend

!macro CONDUIT_STOP_ALL
  !insertmacro CONDUIT_STOP_PROCESS "rusty-conduit-gui.exe"
  !insertmacro CONDUIT_STOP_PROCESS "rusty-conduit-ssh-gui.exe"
  !insertmacro CONDUIT_STOP_PROCESS "conduit-worker.exe"
!macroend

; Detects a legacy "Rusty Conduit (SSH)" install (the pre-rename product name)
; and, unless the installer runs silently, offers to uninstall it. Settings and
; the vault are migrated automatically by the new app on first launch.
!define CONDUIT_LEGACY_UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Rusty Conduit (SSH)"

!macro CONDUIT_OFFER_LEGACY_UNINSTALL
  Push $0
  ReadRegStr $0 HKCU "${CONDUIT_LEGACY_UNINSTALL_KEY}" "UninstallString"
  StrCmp $0 "" 0 +2
    ReadRegStr $0 HKLM "${CONDUIT_LEGACY_UNINSTALL_KEY}" "UninstallString"
  StrCmp $0 "" conduit_legacy_done
  IfSilent conduit_legacy_done
  MessageBox MB_YESNO|MB_ICONQUESTION "The previous app, Rusty Conduit (SSH), is still installed.$\r$\n$\r$\nRusty Conduit GUI replaces it. Your settings and vault are migrated automatically on first launch.$\r$\n$\r$\nUninstall Rusty Conduit (SSH) now?" IDNO conduit_legacy_done
  ExecWait $0
  conduit_legacy_done:
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro CONDUIT_STOP_ALL
  !insertmacro CONDUIT_OFFER_LEGACY_UNINSTALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CONDUIT_STOP_ALL
!macroend
