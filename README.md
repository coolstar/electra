## Thank Comes First
Thanks to u/jakibaki for showing da wae to accomplish this.

## Apps Excluded From Unsandboxing
- PayPal
- Showmax
- Ticketmaster
- Barclays
- Barclaycard
- Vipps
- Halifax
- Standard/Stanbic Bank
- FNBApp
- Lloyds Bank
- Axis Mobile
- SkyBell HD
- Sparkasse
- PushTAN
- MARIO RUN
- ﾊﾟｽﾜｰﾄﾞｶｰﾄﾞ
- 우리은행 원터치개인뱅킹
- ISP/페이북
- PAYCO - 페이코, 혜택까지 똑똑한 간편결제

## Request For More Apps
Create a pull request that adds the apps' name and the bundle identifier (if possible) in the README.md.

# Electra Jailbreak Tookit
for iOS 11.0-11.1.2.
https://coolstar.org/electra/

---

This jailbreak is by the community, and was developed open source.

## Roadmap
See the [open issues](https://github.com/coolstar/electra/issues) for smaller things to work on.

### Currently implemented:
- setuid(0) - no panic
- KCALL - call kernel functions given an address and up to six arguments
- mount / as rw
- amfi bypass? well, run unsigned code (temporary until i figure out a master process which gives everyone everything with the right entitlements etc.)
- amfi**d** fixing up
- jailbreakd that keeps tfp0 task port open and runs a local server listening for commands
- Basic dylib injection into running process
- Working setuid (after calling jailbreakd to fix it up)

### Planned:
- Dpkg/APT port (and maybe Cydia?)
- Structure filesystem more like a traditional jailbreak

## Contributing

* Download the repo, and run the code on your device.
* Make your patches
* PR!
* ???
* Profit :tada:

## I found a bug, how do I report it
[Open a new issue](https://github.com/coolstar/electra/issues/new), **after looking for similar issues already created.**

## Credits

This jailbreak was written by open source contributors. See [the contributors list](https://github.com/coolstar/electra/graphs/contributors) to find out who they are!

* Original patchfinder64 by xerub
* Additions of current gadgets and fix for allproc by ninjaprawn 
* jailbreakd by coolstar
* Extensive contributions by stek29 (sandbox patches, lot's of other stuff)

Please don't rip off any of the code in the jailbreak, but if you do, please credit @theninjaprawn and @coolstarorg.

## License

Note: the async_awake exploit by Ian Beer is not licensed

However, for the additions by Electra, see LICENSE.md
