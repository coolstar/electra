Fun additions to async_await

Original patchfinder64 by xerub, additions of current gadgets + fix for allproc by ninjaprawn

Currently implemented:
- setuid(0) - no panic
- KCALL - call kernel functions given an address and up to six arguments

Planned:
- Patches from KPPless by xerub
- Basic dylib injection into running process

Please don't rip off any code from fun.c, or my additions to the patchfinder. If you do, please credit me (@theninjaprawn)
