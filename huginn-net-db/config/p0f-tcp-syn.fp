;
; p0f - fingerprint database — huginn-net fork
; ---------------------------------------------
;
; Original database by Michal Zalewski <lcamtuf@coredump.cx>
; Distributed under the terms of GNU LGPL.
;
; Modifications and additions (c) 2026 Maximiliano Biandratti
; Additional signatures sourced from Trustable_p0f dataset
;
; Last updated: 2026-06
;

classes = win,unix,other

; ==============
; MTU signatures
; ==============

[tcp:request]

; -----
; Linux
; -----

label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:3.1-3.10
sig   = *:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df,id+:0

; Fun fact: 2.6 with ws=7 seems to be really common for Amazon EC2, while 8 is
; common for Yahoo and Twitter. There seem to be some other (rare) uses, though,
; so not I'm not flagging these signatures in a special way.

label = s:unix:Linux:2.6.x
sig   = *:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,8:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.4.x
sig   = *:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,1:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,2:mss,sok,ts,nop,ws:df,id+:0

; No real traffic seen for 2.2 & 2.0, signatures extrapolated from p0f2 data:

label = s:unix:Linux:2.2.x
sig   = *:64:0:*:mss*11,0:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*22,0:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.0
sig   = *:64:0:*:mss*12,0:mss::0
sig   = *:64:0:*:16384,0:mss::0

; Just to keep people testing locally happy (IPv4 & IPv6):

label = s:unix:Linux:3.x (loopback)
sig   = *:64:0:16396:mss*2,4:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:16376:mss*2,4:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.6.x (loopback)
sig   = *:64:0:16396:mss*2,2:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:16376:mss*2,2:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.4.x (loopback)
sig   = *:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.2.x (loopback)
sig   = *:64:0:3884:mss*8,0:mss,sok,ts,nop,ws:df,id+:0

; Various distinctive flavors of Linux:

label = s:unix:Linux:2.6.x (Google crawler)
sig   = 4:64:0:1430:mss*4,6:mss,sok,ts,nop,ws::0

label = s:unix:Linux:Android
sig   = *:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*44,3:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:65535,8:mss,sok,ts,nop,ws:df,id+:0

; Catch-all rules:

label = g:unix:Linux:3.x
sig   = *:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.4.x-2.6.x
sig   = *:64:0:*:mss*4,*:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x
sig   = *:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x (no timestamps)
sig   = *:64:0:*:*,*:mss,nop,nop,sok,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x (barebone)
sig   = *:64:0:*:*,0:mss:df,id+:0

; -------
; Windows
; -------

label = s:win:Windows:XP
sig   = *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,1:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,2:mss,nop,ws,nop,nop,sok:df,id+:0

label = s:win:Windows:7, 8 or 8.1
sig   = *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,2:mss,nop,ws,sok,ts:df,id+:0

label = s:win:Windows:10
sig   = *:128:0:*:65535,3:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0

; Robots with distinctive fingerprints:

label = s:win:Windows:7 (Websense crawler)
sig   = *:64:0:1380:mss*4,6:mss,nop,nop,ts,nop,ws:df,id+:0
sig   = *:64:0:1380:mss*4,7:mss,nop,nop,ts,nop,ws:df,id+:0

; Catch-all:

label = g:win:Windows:NT kernel 5.x
sig   = *:128:0:*:16384,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:16384,*:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,*:mss,nop,ws,nop,nop,sok:df,id+:0

label = g:win:Windows:NT kernel 6.x
sig   = *:128:0:*:8192,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,*:mss,nop,ws,nop,nop,sok:df,id+:0

label = g:win:Windows:NT kernel
sig   = *:128:0:*:*,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df,id+:0

; ------
; Mac OS
; ------

label = s:unix:Mac OS X:10.x
sig   = *:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,3:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0


label = s:unix:Mac OS X:10.9 or newer (sometimes iPhone or iPad)
sig   = *:64:0:*:65535,4:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:Mac OS X:iPhone or iPad
sig   = *:64:0:*:65535,2:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

; Catch-all rules:

label = g:unix:Mac OS X:
sig   = *:64:0:*:65535,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

; -------
; FreeBSD
; -------

label = s:unix:FreeBSD:9.x
sig   = *:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0

label = s:unix:FreeBSD:8.x
sig   = *:64:0:*:65535,3:mss,nop,ws,sok,ts:df,id+:0

; Catch-all rules:

label = g:unix:FreeBSD:
sig   = *:64:0:*:65535,*:mss,nop,ws,sok,ts:df,id+:0

; -------
; OpenBSD
; -------

label = s:unix:OpenBSD:3.x
sig   = *:64:0:*:16384,0:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0

label = s:unix:OpenBSD:4.x-5.x
sig   = *:64:0:*:16384,3:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0

; -------
; Solaris
; -------

label = s:unix:Solaris:8
sig   = *:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0

label = s:unix:Solaris:10
sig   = *:64:0:*:mss*34,0:mss,nop,ws,nop,nop,sok:df,id+:0

; -------
; OpenVMS
; -------

label = s:unix:OpenVMS:8.x
sig   = 4:128:0:1460:mtu*2,0:mss,nop,ws::0

label = s:unix:OpenVMS:7.x
sig   = 4:64:0:1460:61440,0:mss,nop,ws::0

; --------
; NeXTSTEP
; --------

label = s:other:NeXTSTEP:
sig   = 4:64:0:1024:mss*4,0:mss::0

; -----
; Tru64
; -----

label = s:unix:Tru64:4.x
sig   = 4:64:0:1460:32768,0:mss,nop,ws:df,id+:0

; ----
; NMap
; ----

label = s:!:NMap:SYN scan
sys   = @unix,@win
sig   = *:64-:0:1460:1024,0:mss::0
sig   = *:64-:0:1460:2048,0:mss::0
sig   = *:64-:0:1460:3072,0:mss::0
sig   = *:64-:0:1460:4096,0:mss::0

label = s:!:NMap:OS detection
sys   = @unix,@win
sig   = *:64-:0:265:512,0:mss,sok,ts:ack+:0
sig   = *:64-:0:0:4,10:sok,ts,ws,eol+0:ack+:0
sig   = *:64-:0:1460:1,10:ws,nop,mss,ts,sok:ack+:0
sig   = *:64-:0:536:16,10:mss,sok,ts,ws,eol+0:ack+:0
sig   = *:64-:0:640:4,5:ts,nop,nop,ws,nop,mss:ack+:0
sig   = *:64-:0:1400:63,0:mss,ws,sok,ts,eol+0:ack+:0
sig   = *:64-:0:265:31337,10:ws,nop,mss,ts,sok:ack+:0
sig   = *:64-:0:1460:3,10:ws,nop,mss,sok,nop,nop:ecn,uptr+:0

; -----------
; p0f-sendsyn
; -----------

; These are intentionally goofy, to avoid colliding with any sensible real-world
; stacks. Do not tag these signatures as userspace, unless you want p0f to hide
; the responses!

label = s:unix:p0f:sendsyn utility
sig   = *:192:0:1331:1337,0:mss,nop,eol+18::0
sig   = *:192:0:1331:1337,0:mss,ts,nop,eol+8::0
sig   = *:192:0:1331:1337,5:mss,ws,nop,eol+15::0
sig   = *:192:0:1331:1337,0:mss,sok,nop,eol+16::0
sig   = *:192:0:1331:1337,5:mss,ws,ts,nop,eol+5::0
sig   = *:192:0:1331:1337,0:mss,sok,ts,nop,eol+6::0
sig   = *:192:0:1331:1337,5:mss,ws,sok,nop,eol+13::0
sig   = *:192:0:1331:1337,5:mss,ws,sok,ts,nop,eol+3::0

; -------------
; Odds and ends
; -------------

label = s:other:Blackberry:
sig   = *:128:0:1452:65535,0:mss,nop,nop,sok,nop,nop,ts::0

label = s:other:Nintendo:3DS
sig   = *:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0

label = s:other:Nintendo:Wii
sig   = 4:64:0:1460:32768,0:mss,nop,nop,sok:df,id+:0

label = s:unix:BaiduSpider:
sig   = *:64:0:1460:mss*4,7:mss,sok,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,ws:df,id+:0
sig   = *:64:0:1460:mss*4,2:mss,sok,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,ws:df,id+:0


; ===================================================
; Signatures sourced from Trustable_p0f dataset
; ===================================================

; -------
; Windows
; -------

label = s:win:Windows:10
sig   = 4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1440:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1360:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1360:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1440:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1420:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1420:64952,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1250:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1448:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1380:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1410:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1416:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1298:65535,8:mss,nop,ws,nop,nop,sok::0
sig   = 4:128:0:1400:65535,8:mss,nop,ws,nop,nop,sok::0
sig   = 4:128:0:1410:mss*44,8:mss,nop,ws,nop,nop,sok::0
sig   = 4:128:0:1410:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1460:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+,ecn:0
sig   = 4:128:0:1340:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1364:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1460:mss*6,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1344:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1250:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1260:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1352:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1350:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1436:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+,ecn:0
sig   = 4:128:0:1452:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+,ecn:0
sig   = 4:128:0:1260:mss*52,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1300:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1376:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1376:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:65535,8:mss,nop,ws,nop,nop,sok::0
sig   = 4:128:0:1452:65535,8:mss,nop,ws,nop,nop,sok:df,id+,ecn:0
sig   = 4:128:0:1352:64860,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:65535,8:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:128:0:1428:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:255:0:1440:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1440:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1360:mss*32,12:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1424:59220,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1436:mss*30,12:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:mss*45,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1434:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:65535,6:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:64:0:1460:mss*29,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:mss*44,7:mss,nop,nop,sok,nop,ws:df,id+:0
sig   = 4:64:0:1410:mss*46,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1424:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1436:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1446:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:65535,8:mss,sok,ts,nop,ws:id-:0

label = s:win:Windows:Windows
sig   = 4:128:0:1460:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1400:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1400:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1420:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1380:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1410:65535,8:mss,nop,ws,nop,nop,sok::0
sig   = 4:128:0:1432:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1460:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1432:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1436:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1460:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1298:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1298:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1380:mss*47,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1424:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1424:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1416:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1420:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1364:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1460:8192,8:mss,nop,ws,nop,nop,sok:df,id+,ecn:0
sig   = 4:128:0:1452:mss*44,0:mss,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:mss*45,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1240:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1372:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1372:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1400:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1400:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1408:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1408:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1360:mss*48,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1420:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1444:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:65535,0:mss,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:8192,8:mss,nop,ws,nop,nop,sok:df,id+,ecn:0
sig   = 4:128:0:1412:63443,6:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:65535,0:mss,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:8192,0:mss,nop,nop,sok:df,id+:0
sig   = 4:128:0:1412:mss*44,0:mss,nop,nop,sok:df,id+:0
sig   = 4:128:0:1420:mss*46,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:32768,0:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:63443,6:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:64416,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:65518,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:65535,8:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:128:0:1452:8192,0:mss,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:8192,2:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:128:0:1452:mss*12,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:128:0:1452:mss*44,0:mss,nop,nop,sok:df,id+,ecn:0
sig   = 4:64:0:1376:65535,6:mss,sok,ts,nop,ws:id-:0
sig   = 4:64:0:1460:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1388:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1356:65535,6:mss,sok,ts,nop,ws:id-:0
sig   = 4:64:0:1376:65535,8:mss,sok,ts,nop,ws:id-:0
sig   = 4:64:0:1452:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1432:65535,6:mss,sok,ts,nop,ws:id-:0
sig   = 4:64:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1432:65535,8:mss,sok,ts,nop,ws:id-:0
sig   = 4:64:0:1320:65535,12:mss,nop,ws,sok,ts:df:0
sig   = 4:64:0:1368:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1388:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1390:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1412:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1420:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1390:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1460:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1390:mss*47,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1434:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1452:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1460:mss*20,7:mss,nop,nop,sok,nop,ws:df,id+:0
sig   = 4:64:0:1460:mss*29,11:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1420:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1452:mss*20,7:mss,nop,nop,sok,nop,ws:df,id+:0
sig   = 4:64:0:1460:mss*29,12:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:mss*44,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,8:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:64:0:1452:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1360:65535,6:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1400:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1380:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1420:mss*44,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1452:mss*20,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,8:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:64:0:1412:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1412:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1452:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1452:mss*44,7:mss,nop,nop,sok,nop,ws:df,id+:0
sig   = 4:64:0:1452:mss*45,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = 4:64:0:1460:mss*20,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:mss*45,7:mss,sok,ts,nop,ws:df,id+:0

; ---
; OSX
; ---

label = s:unix:OS X:10.15.7
sig   = 4:64:0:1460:mss*29,10:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:OS X:OS X
sig   = 4:64:0:1412:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1410:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1410:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-:0
sig   = 4:64:0:1298:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-:0
sig   = 4:64:0:1400:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-:0
sig   = 4:64:0:1410:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1410:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:id-:0
sig   = 4:64:0:1352:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1412:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1452:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1452:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1452:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1452:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-:0

label = s:unix:OSX:OSX
sig   = 4:64:0:1452:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1420:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1460:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1412:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1420:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1460:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1452:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1452:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1298:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1400:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1420:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1372:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1400:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1400:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1408:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1452:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1416:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1416:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0

label = s:unix:iOS:iOS
sig   = 4:255:0:1330:65535,9:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:255:0:1390:65535,9:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:255:0:1332:65535,7:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1360:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1400:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1360:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1452:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1388:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1348:65535,12:mss,nop,ws,sok,ts:df,ecn:0
sig   = 4:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1460:65535,12:mss,nop,ws,sok,ts:df,ecn:0
sig   = 4:64:0:1410:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1410:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1220:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1360:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1400:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1420:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1390:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1360:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1368:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1388:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1390:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1250:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1300:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1322:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:ecn:0
sig   = 4:64:0:1380:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1408:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1410:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1320:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1332:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1332:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1339:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1339:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1340:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1360:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1380:65535,13:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1390:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1390:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1416:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1436:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1240:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1298:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1360:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1380:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1390:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1::0
sig   = 4:64:0:1412:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1424:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1220:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1298:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1298:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1298:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1340:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1344:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1364:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1390:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1410:65535,5:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1416:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:id-,ecn:0
sig   = 4:64:0:1300:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1364:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1446:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1250:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1344:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1432:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1440:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1372:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1452:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = 4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+,ecn:0
sig   = 4:64:0:1376:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1376:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0
sig   = 4:64:0:1428:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1452:65535,7:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
sig   = 4:64:0:1452:65535,7:mss,nop,ws,nop,nop,ts,sok,eol+1:df:0

; -----
; Linux
; -----

label = s:unix:Linux:Linux
sig   = 4:64:0:1412:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:mss*44,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:mss*45,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1298:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:mss*44,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1420:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:mss*44,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:mss*44,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1420:mss*44,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:mss*44,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1416:mss*46,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:mss*44,9:mss,sok,ts,nop,ws:df,id+:0

; -------
; Android
; -------

label = s:unix:Android:Android
sig   = 4:64:0:1360:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1360:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1360:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1220:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1420:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1460:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1400:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1420:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1420:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1424:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1420:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1440:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1440:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1220:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1408:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1408:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1432:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1440:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1318:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1340:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1390:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1416:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1432:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1436:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:65535,9:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1240:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1240:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1298:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1298:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1298:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1310:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1332:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1339:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1360:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1380:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1380:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1410:65535,10:mss,sok,ts,nop,ws::0
sig   = 4:64:0:1432:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:65535,9:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1240:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1298:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1298:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1310:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1340:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1344:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1364:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1370:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1380:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1380:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1410:65535,8:mss,sok,ts,nop,ws::0
sig   = 4:64:0:1410:65535,9:mss,sok,ts,nop,ws::0
sig   = 4:64:0:1412:65535,12:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1416:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1416:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1416:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1424:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1424:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1440:65535,10:mss,sok,ts,nop,ws:df:0
sig   = 4:64:0:1452:65535,9:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1460:65535,12:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1300:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1300:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1340:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1364:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1364:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1370:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1220:65535,4:mss,nop,ws,sok,ts:df,id+:0
sig   = 4:64:0:1250:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1344:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1344:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1432:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,12:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1240:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1372:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1372:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1372:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1372:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1400:65535,9:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1408:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1408:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1376:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1376:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1412:65535,9:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1420:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1460:62727,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1292:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1310:65535,8:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1310:65535,9:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1324:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1364:65535,10:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1416:65535,7:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1416:65535,9:mss,sok,ts,nop,ws:df,id+,ecn:0
sig   = 4:64:0:1428:65535,10:mss,sok,ts,nop,ws:df,id+:0
sig   = 4:64:0:1452:65535,8:mss,sok,ts,nop,ws::0
sig   = 4:64:0:1452:mss*29,8:mss,sok,ts,nop,ws:df,id+:0

; -----
; Other
; -----

label = s:other:Other:Other
sig   = 4:64:0:1460:62727,7:mss,sok,ts,nop,ws:df,id+:0
