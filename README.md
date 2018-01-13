Electra Jailbeak Tookit for iOS 11.0-11.1.2

https://coolstar.org/electra/

Original patchfinder64 by xerub, additions of current gadgets + fix for allproc by ninjaprawn + jailbreakd by coolstar

Currently implemented:
- setuid(0) - no panic
- KCALL - call kernel functions given an address and up to six arguments
- mount / as rw
- amfi bypass? well, run unsigned code (temporary until i figure out a master process which gives everyone everything with the right entitlements etc.)
- amfi**d** fixing up
- jailbreakd that keeps tfp0 task port open and runs a local server listening for commands
- Basic dylib injection into running process

Planned:
- Dpkg/APT port (and maybe Cydia?)
- working setuid0
- structure filesystem more like a traditional jailbreak

If libproc.h doesn't exist, delete the line

Please don't rip off any code from fun.c, or my additions to the patchfinder. If you do, please credit @theninjaprawn and @coolstarorg
