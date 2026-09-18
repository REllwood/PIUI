# Hostile Markdown containment fixture

This fixture contains inert probes only. Every network host uses the reserved `.invalid` suffix and every local-looking value is synthetic.

## Raw active HTML, SVG and MathML

<script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__ = true; window.__TAURI_INTERNALS__.invoke('host_status')</script>
<script src="/src/main.tsx"></script>
<custom-fetch-probe data-url="/synthetic/private/custom-element-canary"></custom-fetch-probe>
<svg onload="window.__PIUI_MARKDOWN_EVENT_EXECUTED__=true"><script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script><image href="https://svg-probe.invalid/pixel.png" /></svg>
<math href="javascript:window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true"><mtext>math probe</mtext></math>
<iframe src="https://frame-probe.invalid/" srcdoc="<script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script>"></iframe>
<object data="https://object-probe.invalid/object"></object>
<embed src="https://embed-probe.invalid/embed">
<base href="https://base-probe.invalid/">
<meta http-equiv="refresh" content="0;url=https://refresh-probe.invalid/">
<form action="https://form-probe.invalid/submit"><input name="probe" formaction="https://form-action-probe.invalid/submit"></form>
<details ontoggle="window.__PIUI_MARKDOWN_EVENT_EXECUTED__=true"><summary>event probe</summary></details>
<template><img src="https://template-probe.invalid/pixel.png"></template>

## Event attributes and CSS resource probes

<img src="https://event-probe.invalid/pixel.png" srcset="https://srcset-probe.invalid/a.png 2x" style="background:url(https://style-attribute-probe.invalid/pixel.png)" onerror="window.__PIUI_MARKDOWN_EVENT_EXECUTED__=true">
<a href="https://raw-anchor-probe.invalid/" onclick="window.__PIUI_MARKDOWN_EVENT_EXECUTED__=true">raw anchor</a>
<style>@import url(https://css-import-probe.invalid/sheet.css); .probe { background: url(/synthetic/private/css-canary.png); }</style>
<link rel="stylesheet" href="https://stylesheet-probe.invalid/sheet.css">
<link rel="preload" as="image" href="/@fs/synthetic/private/preload-canary.png">
<link rel="prefetch" href="/synthetic/private/prefetch-canary">
<picture><source srcset="/synthetic/private/source-canary.png 1x"><img src="/synthetic/private/picture-canary.png"></picture>
<img srcset="/synthetic/private/srcset-canary.png 1x, /synthetic/private/srcset-canary-2.png 2x">
<a href="/synthetic/private/download-canary" ping="/synthetic/private/ping-canary" download>download probe</a>

## External-link policy probes

[Safe documentation](https://safe.example.invalid/guide?q=visible)
<https://autolink.example.invalid/reference>
Bare GFM link: https://bare-autolink.example.invalid/notes

[HTTP blocked](http://cleartext.example.invalid/)
[JavaScript blocked](javascript:window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true)
[Mixed JavaScript blocked](JaVaScRiPt:window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true)
[Entity JavaScript blocked](java&#x73;cript&#x3a;window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true)
[Double entity blocked](java&amp;#x73;cript&amp;#x3a;alert(1))
[Percent scheme blocked](%6aavascript%3aalert(1))
[Double percent blocked](%256aavascript%253aalert(1))
[Encoded HTTPS delimiters blocked](https:%2f%2fencoded.example.invalid/)
[Data blocked](data:text/html,<script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script>)
[Blob blocked](blob:https://blob-probe.invalid/00000000-0000-0000-0000-000000000000)
[File blocked](file:///synthetic/private/example.txt)
[Asset blocked](asset://localhost/synthetic/project/file.png)
[Tauri blocked](tauri://localhost/host_status)
[IPC blocked](ipc://localhost/bridge_send)
[VBScript blocked](vbscript:msgbox(1))
[Custom command blocked](piui-command:host_status)
[Mail blocked](mailto:probe@example.invalid)
[Scheme-relative blocked](//scheme-relative-probe.invalid/path)
[Root-relative blocked](/synthetic/admin)
[Relative blocked](synthetic/relative)
[Fragment blocked](#hostile-fragment)
[Credentials blocked](https://safe.example.invalid@credential-probe.invalid/path)
[Backslash authority blocked](https://safe.example.invalid\@backslash-probe.invalid/path)
[Encoded authority blocked](https://percent%2eprobe.invalid/path)
[Unexpected port blocked](https://port-probe.invalid:444/path)
[Unicode whitespace blocked](https://unicode-space.example.invalid/ path)
[Zero width blocked](https://zero-width.example.invalid/​path)
[Bidi blocked](https://bidi.example.invalid/‮path)
[Full-width scheme blocked](ｈｔｔｐｓ://fullwidth.example.invalid/path)

## Untrusted image probes

![Remote HTTPS image](https://remote-image-probe.invalid/pixel.png)
![Remote HTTP image](http://remote-image-probe.invalid/pixel.png)
![Scheme-relative image](//scheme-relative-image.invalid/pixel.png)
![Relative image](synthetic/pixel.png)
![Root relative image](/synthetic/pixel.png)
![Private same-origin canary](/synthetic/private/image-canary.png)
![Direct test-host capability path](/__piui_markdown_asset__/0123456789abcdef0123456789abcdef.png)
![Data SVG image](data:image/svg+xml,<svg onload="window.__PIUI_MARKDOWN_EVENT_EXECUTED__=true"/>)
![Blob image](blob:https://blob-image.invalid/00000000-0000-0000-0000-000000000000)
![File image](file:///synthetic/private/pixel.png)
![Direct asset image](asset://localhost/synthetic/private/pixel.png)
![IPC image](ipc://localhost/pixel.png)
![Tauri image](tauri://localhost/pixel.png)
![Custom image](piui-resource:synthetic)
![](https://unnamed-image.invalid/pixel.png "hostile title")
![Unknown opaque image](piui-asset-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
![Malformed opaque image](piui-asset-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
![Short opaque image](piui-asset-abc)

## GFM positive controls

| Surface | Expected behaviour |
| --- | --- |
| Table | Semantic and internally scrollable |
| ~~Strikethrough~~ | Rendered as deleted text |

- [x] Completed task
- [ ] Incomplete task

## Code remains React text

```tsx
</code><script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script>
<img src="https://code-image-probe.invalid/pixel.png" onerror="window.__PIUI_MARKDOWN_EVENT_EXECUTED__=true">
window.__TAURI_INTERNALS__.invoke('bridge_send', { command: 'host_status' })
const tauriLookingCapability = 'piui-asset-ffffffffffffffffffffffffffffffff'
```

```unknown-language-${window.__TAURI_INTERNALS__}
<script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script>
```

## Deterministic syntax-highlighting budget controls

The following blocks prove that packaged rendering falls back to escaped text when real Shiki work or render limits are reached.

```typescript
const A26_RENDER_BUDGET_START: number = 0;
const renderBudget001: number = 1;
const renderBudget002: number = 2;
const renderBudget003: number = 3;
const renderBudget004: number = 4;
const renderBudget005: number = 5;
const renderBudget006: number = 6;
const renderBudget007: number = 7;
const renderBudget008: number = 8;
const renderBudget009: number = 9;
const renderBudget010: number = 10;
const renderBudget011: number = 11;
const renderBudget012: number = 12;
const renderBudget013: number = 13;
const renderBudget014: number = 14;
const renderBudget015: number = 15;
const renderBudget016: number = 16;
const renderBudget017: number = 17;
const renderBudget018: number = 18;
const renderBudget019: number = 19;
const renderBudget020: number = 20;
const renderBudget021: number = 21;
const renderBudget022: number = 22;
const renderBudget023: number = 23;
const renderBudget024: number = 24;
const renderBudget025: number = 25;
const renderBudget026: number = 26;
const renderBudget027: number = 27;
const renderBudget028: number = 28;
const renderBudget029: number = 29;
const renderBudget030: number = 30;
const renderBudget031: number = 31;
const renderBudget032: number = 32;
const renderBudget033: number = 33;
const renderBudget034: number = 34;
const renderBudget035: number = 35;
const renderBudget036: number = 36;
const renderBudget037: number = 37;
const renderBudget038: number = 38;
const renderBudget039: number = 39;
const renderBudget040: number = 40;
const renderBudget041: number = 41;
const renderBudget042: number = 42;
const renderBudget043: number = 43;
const renderBudget044: number = 44;
const renderBudget045: number = 45;
const renderBudget046: number = 46;
const renderBudget047: number = 47;
const renderBudget048: number = 48;
const renderBudget049: number = 49;
const renderBudget050: number = 50;
const renderBudget051: number = 51;
const renderBudget052: number = 52;
const renderBudget053: number = 53;
const renderBudget054: number = 54;
const renderBudget055: number = 55;
const renderBudget056: number = 56;
const renderBudget057: number = 57;
const renderBudget058: number = 58;
const renderBudget059: number = 59;
const renderBudget060: number = 60;
const renderBudget061: number = 61;
const renderBudget062: number = 62;
const renderBudget063: number = 63;
const renderBudget064: number = 64;
const renderBudget065: number = 65;
const renderBudget066: number = 66;
const renderBudget067: number = 67;
const renderBudget068: number = 68;
const renderBudget069: number = 69;
const renderBudget070: number = 70;
const renderBudget071: number = 71;
const renderBudget072: number = 72;
const renderBudget073: number = 73;
const renderBudget074: number = 74;
const renderBudget075: number = 75;
const renderBudget076: number = 76;
const renderBudget077: number = 77;
const renderBudget078: number = 78;
const renderBudget079: number = 79;
const renderBudget080: number = 80;
const renderBudget081: number = 81;
const renderBudget082: number = 82;
const renderBudget083: number = 83;
const renderBudget084: number = 84;
const renderBudget085: number = 85;
const renderBudget086: number = 86;
const renderBudget087: number = 87;
const renderBudget088: number = 88;
const renderBudget089: number = 89;
const renderBudget090: number = 90;
const renderBudget091: number = 91;
const renderBudget092: number = 92;
const renderBudget093: number = 93;
const renderBudget094: number = 94;
const renderBudget095: number = 95;
const renderBudget096: number = 96;
const renderBudget097: number = 97;
const renderBudget098: number = 98;
const renderBudget099: number = 99;
const renderBudget100: number = 100;
const renderBudget101: number = 101;
const renderBudget102: number = 102;
const renderBudget103: number = 103;
const renderBudget104: number = 104;
const renderBudget105: number = 105;
const renderBudget106: number = 106;
const renderBudget107: number = 107;
const renderBudget108: number = 108;
const renderBudget109: number = 109;
const renderBudget110: number = 110;
const renderBudget111: number = 111;
const renderBudget112: number = 112;
const renderBudget113: number = 113;
const renderBudget114: number = 114;
const renderBudget115: number = 115;
const renderBudget116: number = 116;
const renderBudget117: number = 117;
const renderBudget118: number = 118;
const renderBudget119: number = 119;
const renderBudget120: number = 120;
const renderBudget121: number = 121;
const renderBudget122: number = 122;
const renderBudget123: number = 123;
const renderBudget124: number = 124;
const renderBudget125: number = 125;
const renderBudget126: number = 126;
const renderBudget127: number = 127;
const renderBudget128: number = 128;
const renderBudget129: number = 129;
const renderBudget130: number = 130;
const renderBudget131: number = 131;
const renderBudget132: number = 132;
const renderBudget133: number = 133;
const renderBudget134: number = 134;
const renderBudget135: number = 135;
const renderBudget136: number = 136;
const renderBudget137: number = 137;
const renderBudget138: number = 138;
const renderBudget139: number = 139;
const renderBudget140: number = 140;
const renderBudget141: number = 141;
const renderBudget142: number = 142;
const renderBudget143: number = 143;
const renderBudget144: number = 144;
const renderBudget145: number = 145;
const renderBudget146: number = 146;
const renderBudget147: number = 147;
const renderBudget148: number = 148;
const renderBudget149: number = 149;
const renderBudget150: number = 150;
const renderBudget151: number = 151;
const renderBudget152: number = 152;
const renderBudget153: number = 153;
const renderBudget154: number = 154;
const renderBudget155: number = 155;
const renderBudget156: number = 156;
const renderBudget157: number = 157;
const renderBudget158: number = 158;
const renderBudget159: number = 159;
const renderBudget160: number = 160;
const renderBudget161: number = 161;
const renderBudget162: number = 162;
const renderBudget163: number = 163;
const renderBudget164: number = 164;
const renderBudget165: number = 165;
const renderBudget166: number = 166;
const renderBudget167: number = 167;
const renderBudget168: number = 168;
const renderBudget169: number = 169;
const renderBudget170: number = 170;
const renderBudget171: number = 171;
const renderBudget172: number = 172;
const renderBudget173: number = 173;
const renderBudget174: number = 174;
const renderBudget175: number = 175;
const renderBudget176: number = 176;
const renderBudget177: number = 177;
const renderBudget178: number = 178;
const renderBudget179: number = 179;
const renderBudget180: number = 180;
const renderBudget181: number = 181;
const renderBudget182: number = 182;
const renderBudget183: number = 183;
const renderBudget184: number = 184;
const renderBudget185: number = 185;
const renderBudget186: number = 186;
const renderBudget187: number = 187;
const renderBudget188: number = 188;
const renderBudget189: number = 189;
const renderBudget190: number = 190;
const renderBudget191: number = 191;
const renderBudget192: number = 192;
const renderBudget193: number = 193;
const renderBudget194: number = 194;
const renderBudget195: number = 195;
const renderBudget196: number = 196;
const renderBudget197: number = 197;
const renderBudget198: number = 198;
const renderBudget199: number = 199;
const renderBudget200: number = 200;
const renderBudget201: number = 201;
const renderBudget202: number = 202;
const renderBudget203: number = 203;
const renderBudget204: number = 204;
const renderBudget205: number = 205;
const renderBudget206: number = 206;
const renderBudget207: number = 207;
const renderBudget208: number = 208;
const renderBudget209: number = 209;
const renderBudget210: number = 210;
const renderBudget211: number = 211;
const renderBudget212: number = 212;
const renderBudget213: number = 213;
const renderBudget214: number = 214;
const renderBudget215: number = 215;
const renderBudget216: number = 216;
const renderBudget217: number = 217;
const renderBudget218: number = 218;
const renderBudget219: number = 219;
const renderBudget220: number = 220;
const renderBudget221: number = 221;
const renderBudget222: number = 222;
const renderBudget223: number = 223;
const renderBudget224: number = 224;
const renderBudget225: number = 225;
const renderBudget226: number = 226;
const renderBudget227: number = 227;
const renderBudget228: number = 228;
const renderBudget229: number = 229;
const renderBudget230: number = 230;
const renderBudget231: number = 231;
const renderBudget232: number = 232;
const renderBudget233: number = 233;
const renderBudget234: number = 234;
const renderBudget235: number = 235;
const renderBudget236: number = 236;
const renderBudget237: number = 237;
const renderBudget238: number = 238;
const renderBudget239: number = 239;
const renderBudget240: number = 240;
const renderBudget241: number = 241;
const renderBudget242: number = 242;
const renderBudget243: number = 243;
const renderBudget244: number = 244;
const renderBudget245: number = 245;
const renderBudget246: number = 246;
const renderBudget247: number = 247;
const renderBudget248: number = 248;
const renderBudget249: number = 249;
const renderBudget250: number = 250;
const renderBudget251: number = 251;
const renderBudget252: number = 252;
const renderBudget253: number = 253;
const renderBudget254: number = 254;
const renderBudget255: number = 255;
const renderBudget256: number = 256;
const renderBudget257: number = 257;
const renderBudget258: number = 258;
const renderBudget259: number = 259;
const renderBudget260: number = 260;
const renderBudget261: number = 261;
const renderBudget262: number = 262;
const renderBudget263: number = 263;
const renderBudget264: number = 264;
const renderBudget265: number = 265;
const renderBudget266: number = 266;
const renderBudget267: number = 267;
const renderBudget268: number = 268;
const renderBudget269: number = 269;
const renderBudget270: number = 270;
const renderBudget271: number = 271;
const renderBudget272: number = 272;
const renderBudget273: number = 273;
const renderBudget274: number = 274;
const renderBudget275: number = 275;
const renderBudget276: number = 276;
const renderBudget277: number = 277;
const renderBudget278: number = 278;
const renderBudget279: number = 279;
const renderBudget280: number = 280;
const renderBudget281: number = 281;
const renderBudget282: number = 282;
const renderBudget283: number = 283;
const renderBudget284: number = 284;
const renderBudget285: number = 285;
const renderBudget286: number = 286;
const renderBudget287: number = 287;
const renderBudget288: number = 288;
const renderBudget289: number = 289;
const renderBudget290: number = 290;
const renderBudget291: number = 291;
const renderBudget292: number = 292;
const renderBudget293: number = 293;
const renderBudget294: number = 294;
const renderBudget295: number = 295;
const renderBudget296: number = 296;
const renderBudget297: number = 297;
const renderBudget298: number = 298;
const renderBudget299: number = 299;
const renderBudget300: number = 300;
const renderBudget301: number = 301;
const renderBudget302: number = 302;
const renderBudget303: number = 303;
const renderBudget304: number = 304;
const renderBudget305: number = 305;
const renderBudget306: number = 306;
const renderBudget307: number = 307;
const renderBudget308: number = 308;
const renderBudget309: number = 309;
const renderBudget310: number = 310;
const renderBudget311: number = 311;
const renderBudget312: number = 312;
const renderBudget313: number = 313;
const renderBudget314: number = 314;
const renderBudget315: number = 315;
const renderBudget316: number = 316;
const renderBudget317: number = 317;
const renderBudget318: number = 318;
const renderBudget319: number = 319;
const renderBudget320: number = 320;
const renderBudget321: number = 321;
const renderBudget322: number = 322;
const renderBudget323: number = 323;
const renderBudget324: number = 324;
const renderBudget325: number = 325;
const renderBudget326: number = 326;
const renderBudget327: number = 327;
const renderBudget328: number = 328;
const renderBudget329: number = 329;
const renderBudget330: number = 330;
const renderBudget331: number = 331;
const renderBudget332: number = 332;
const renderBudget333: number = 333;
const renderBudget334: number = 334;
const renderBudget335: number = 335;
const renderBudget336: number = 336;
const renderBudget337: number = 337;
const renderBudget338: number = 338;
const renderBudget339: number = 339;
const renderBudget340: number = 340;
const renderBudget341: number = 341;
const renderBudget342: number = 342;
const renderBudget343: number = 343;
const renderBudget344: number = 344;
const renderBudget345: number = 345;
const renderBudget346: number = 346;
const renderBudget347: number = 347;
const renderBudget348: number = 348;
const renderBudget349: number = 349;
const renderBudget350: number = 350;
const A26_RENDER_BUDGET_END: number = 351;
```

```typescript
// A26_WORK_PRIMER_START pppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_002 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_003 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_004 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_005 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_006 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_007 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_008 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_009 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_010 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_011 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_012 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_013 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_014 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_015 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_016 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_017 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_018 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_019 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_020 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_021 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_022 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_023 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_024 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_025 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_026 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_027 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_028 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_029 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_030 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_031 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_032 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_033 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_034 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_035 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_036 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_037 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_038 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_039 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_040 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_041 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_042 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_043 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_044 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_045 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_046 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_047 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_048 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_049 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_050 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_051 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_052 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_053 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_054 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_055 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_056 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_057 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_058 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_059 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_060 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_061 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_062 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_063 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_064 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_065 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_066 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_067 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_068 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_069 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_070 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_071 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_072 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_073 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_074 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_075 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_076 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_077 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_078 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_079 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_080 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_081 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_082 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_083 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_084 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_085 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_086 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_087 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_088 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_089 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_090 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_091 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_092 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_093 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_094 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_095 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_096 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_097 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_098 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_099 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_100 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_101 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_102 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_103 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_104 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_105 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_106 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_107 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_108 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_109 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_110 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_111 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_112 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_113 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_114 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_115 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_116 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_117 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_118 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_119 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_120 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_121 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_122 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_123 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_124 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_125 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_126 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_127 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_128 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_129 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_130 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_131 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_132 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_133 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_134 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_135 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_136 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_137 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_138 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_139 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_140 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_141 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_142 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_143 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_144 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_145 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_146 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_147 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_148 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_149 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_150 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_151 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_152 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_153 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_154 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_155 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_156 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_157 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_158 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_159 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_160 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_161 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_162 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_163 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_164 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_165 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_166 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_167 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_168 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_169 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_170 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_171 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_172 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_173 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_174 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_175 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_176 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_177 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_178 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_179 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_180 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_181 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_182 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_183 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_184 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_185 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_186 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_187 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_188 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_189 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_190 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_191 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_192 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_193 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_194 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_195 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_196 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_197 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_198 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_199 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_200 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_201 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_202 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_203 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_204 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_205 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_206 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_207 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_208 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_209 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_210 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_211 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_212 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_213 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_214 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_215 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_216 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_217 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_218 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_219 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_220 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_221 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_222 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_223 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_224 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_225 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_226 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_227 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_228 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_229 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_230 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_231 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_232 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_233 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_234 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_235 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_236 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_237 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_238 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_239 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_240 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_241 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_242 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_243 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_244 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_245 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_246 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_247 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_248 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_249 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_250 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_251 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_252 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_253 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_254 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_255 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_256 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_257 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_258 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_259 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_260 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_261 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_262 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_263 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_264 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_265 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_266 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_267 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_268 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_269 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_270 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_271 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_272 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_273 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_274 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_275 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_276 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_277 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_278 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_279 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_280 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_281 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_282 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_283 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_284 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_285 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_286 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_287 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_288 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_289 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_290 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_291 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_292 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_293 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_294 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_295 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_296 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_297 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_298 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_299 pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
// A26_WORK_PRIMER_END_300 ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp
```

```typescript
// A26_WORK_BUDGET_START wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww
wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww A26_WORK_BUDGET_END
```

Inline code is inert: `</span><script>window.__PIUI_MARKDOWN_SCRIPT_EXECUTED__=true</script>`.

## Pathological-shape samples

> > > > > > > > Bounded nested quote sample

1. first list
   1. nested list
      1. deeper list
         - bounded item

Delimiter storm sample: ***___~~~```[[[]]]((())){{{}}}***___~~~

Tauri-looking strings are prose only: `invoke`, `host_status`, `bridge_send`, `sidecar_start`, `workspace_authorise`, `approval_submit`, `__TAURI_INTERNALS__`, and `piui-asset-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.

[Overlong destination blocked](https://long-link.example.invalid/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)
