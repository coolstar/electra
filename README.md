Fun additions to async_await

Original patchfinder64 by xerub, additions of current gadgets + fix for allproc by ninjaprawn

Currently implemented:
- setuid(0) - no panic
- KCALL - call kernel functions given an address and up to six arguments
- mount / as rw
- amfi bypass? well, run unsigned code (temporary until i figure out a master process which gives everyone everything with the right entitlements etc.)

Planned:
- amfi**d** fixing up (might consider putting into a seperate daemon to constantly do what Ian Beer was doing in mach_portal/triplefetch
- Basic dylib injection into running process

If libproc.h doesn't exist, delete the line

Please don't rip off any code from fun.c, or my additions to the patchfinder. If you do, please credit me (@theninjaprawn)
