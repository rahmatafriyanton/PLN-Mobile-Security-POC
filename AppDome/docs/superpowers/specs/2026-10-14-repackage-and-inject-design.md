# Repackage and Inject Design

## Goal

Provide one reproducible shell entry point that converts the original PLN Mobile
APK into the verified Frida-ready build, installs it on the selected emulator,
attaches Frida, displays a `Frida injected` toast and dialog, and remains attached
until the operator presses Ctrl+C.

## Files

- `emulator/repackage-and-inject.sh`: validates prerequisites, creates a temporary
  apktool workspace, materializes the fixed runtime bytes embedded in the script,
  applies the verified patches, rebuilds/signs/installs the APK, starts Frida
  server, launches the app, and attaches the indicator script.
- `emulator/frida-injected.js`: displays the toast and dialog on the Android main
  thread, reports readiness, and keeps the script loaded.

No DEX file is stored in the repository. Because the source APK is fixed, the
verified compressed runtime bytes are embedded directly in the shell script,
expanded only inside its temporary workspace, and deleted by its exit trap.

## Patch flow

1. Decode the input APK with apktool.
2. Replace the Appdome application bootstrap with `android.app.Application` and
   remove its component factory.
3. Disable Impeller to avoid the confirmed emulator Vulkan deadlock.
4. Reconstruct `com.app.plnmobile.MainActivity` as a plain `FlutterActivity`.
5. Skip only the missing `MobileScannerPlugin` registration so later plugins,
   including SharedPreferences, register normally.
6. Build with apktool, append the patched runtime DEX, zipalign, debug-sign, and
   install the result.
7. Start the existing Frida 16.5.2 server alias, launch the app, resolve its PID,
   and attach using the Frida CLI.

## Failure handling and verification

The shell uses strict mode, an isolated temporary directory, cleanup traps, explicit
tool/file checks, APK signature verification, bounded waits for server/PID readiness,
and clear errors. Verification requires a successful build/install, visible app PID,
Frida readiness message, toast/dialog injection, and an attached session that remains
alive until Ctrl+C.

The script does not clear application data unless installation fails due to an
incompatible signature; in that case it stops and prints the explicit uninstall
command instead of deleting data automatically.
