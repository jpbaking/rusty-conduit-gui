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

!macro NSIS_HOOK_PREINSTALL
  !insertmacro CONDUIT_STOP_ALL
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro CONDUIT_STOP_ALL
!macroend
