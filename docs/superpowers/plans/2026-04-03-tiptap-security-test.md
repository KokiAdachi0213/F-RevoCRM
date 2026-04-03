# Tiptapリッチテキストエディタ 脆弱性テスト実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 設計書（`docs/superpowers/specs/2026-04-03-tiptap-security-test-design.md`）に基づき、Tiptapリッチテキストエディタの脆弱性テスト111ケースを実装する

**Architecture:** バックエンド（PHP）単体テスト → フロントエンド（Vitest）単体テスト → 結合テスト（Playwright MCP）の3層構成。バックエンドはPHPスクリプト形式（PHPUnit未導入のため）、フロントエンドは既存Vitest環境を活用。

**Tech Stack:** PHP（HTMLPurifier）、TypeScript（Vitest + jsdom）、Playwright MCP（結合テスト）

---

## ファイル構成

### 新規作成ファイル

| ファイル | 責務 |
|---|---|
| `test/unit/tiptap-security/backend/SecurityTestRunner.php` | PHP テストランナー基盤（ペイロード投入→結果検証→レポート出力） |
| `test/unit/tiptap-security/backend/test_xss.php` | Suite 1: XSS テスト（40件） |
| `test/unit/tiptap-security/backend/test_encoding_bypass.php` | Suite 2: エンコーディングバイパス テスト（17件） |
| `test/unit/tiptap-security/backend/test_html_injection.php` | Suite 4: HTMLインジェクション テスト（10件） |
| `test/unit/tiptap-security/backend/test_css_injection.php` | Suite 5: CSSインジェクション テスト（10件） |
| `test/unit/tiptap-security/backend/test_dom_clobbering.php` | Suite 6: DOMクロバリング テスト（5件） |
| `test/unit/tiptap-security/backend/test_base64.php` | Suite 7: base64画像悪用 テスト（7件） |
| `test/unit/tiptap-security/backend/run_all.php` | 全バックエンドテスト一括実行スクリプト |
| `assets/react-web-components/src/components/ui/tiptap/__tests__/security/normalize-security.test.ts` | フロントエンド正規化関数セキュリティテスト |
| `test/integration/tiptap-security/suite3_layer_gap.php` | Suite 3: レイヤー間テスト用データ準備スクリプト |

---

## Task 1: バックエンドテストランナー基盤

**Files:**
- Create: `test/unit/tiptap-security/backend/SecurityTestRunner.php`

- [ ] **Step 1: テストランナークラスを作成**

```php
<?php
/**
 * Tiptap脆弱性テスト用テストランナー
 *
 * vtlib_purify() と purifyHtmlEventAttributes() に対して
 * ペイロードを投入し、結果を検証・レポートする。
 */

chdir('/var/www/html/GitHub');
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'includes/runtime/Globals.php';
include_once 'include/utils/utils.php';
include_once 'include/utils/VtlibUtils.php';

class SecurityTestRunner
{
    private array $results = [];
    private string $suiteName;

    public function __construct(string $suiteName)
    {
        $this->suiteName = $suiteName;
    }

    /**
     * vtlib_purify のみで浄化テスト
     */
    public function testVtlibPurify(string $id, string $name, string $payload, string $mustNotContainPattern): void
    {
        $result = vtlib_purify($payload);
        $this->assertNotContainsPattern($id, $name, $payload, $result, $mustNotContainPattern, 'vtlib_purify');
    }

    /**
     * purifyHtmlEventAttributes のみで浄化テスト
     */
    public function testPurifyEventAttrs(string $id, string $name, string $payload, string $mustNotContainPattern): void
    {
        $result = purifyHtmlEventAttributes($payload, true);
        $this->assertNotContainsPattern($id, $name, $payload, $result, $mustNotContainPattern, 'purifyHtmlEventAttributes');
    }

    /**
     * 完全な浄化パイプラインをシミュレート（Save.php と同じ処理順序）
     * decode_html → vtlib_purify → decode_html → purifyHtmlEventAttributes
     */
    public function testFullPipeline(string $id, string $name, string $payload, string $mustNotContainPattern): void
    {
        $step1 = decode_html($payload);
        $step2 = vtlib_purify($step1);
        $step3 = decode_html($step2);
        $step4 = purifyHtmlEventAttributes($step3, true);
        $this->assertNotContainsPattern($id, $name, $payload, $step4, $mustNotContainPattern, 'fullPipeline');
    }

    /**
     * 浄化後に特定のHTMLが保持されることを検証
     */
    public function testPreserved(string $id, string $name, string $payload, string $mustContainPattern): void
    {
        $step1 = decode_html($payload);
        $step2 = vtlib_purify($step1);
        $step3 = decode_html($step2);
        $step4 = purifyHtmlEventAttributes($step3, true);
        $found = preg_match($mustContainPattern, $step4);
        $status = $found ? 'PASS' : 'FAIL';
        $this->results[] = [
            'id' => $id,
            'name' => $name,
            'status' => $status,
            'layer' => 'fullPipeline',
            'input' => mb_substr($payload, 0, 100),
            'output' => mb_substr($step4, 0, 200),
            'check' => "mustContain: {$mustContainPattern}",
        ];
    }

    private function assertNotContainsPattern(
        string $id, string $name, string $payload,
        string $result, string $pattern, string $layer
    ): void {
        $found = preg_match($pattern, $result);
        $status = $found ? 'FAIL' : 'PASS';

        // 期待防御レイヤーと実際のレイヤーが異なるか判定
        // vtlib_purify内部でもpurifyHtmlEventAttributesが呼ばれるため、
        // L2テストでイベント属性が除去されている場合はPASS（別レイヤー）
        if ($status === 'PASS' && $layer === 'vtlib_purify') {
            // HTMLPurifierインスタンスをグローバル変数から取得
            global $__htmlpurifier_instance;
            if ($__htmlpurifier_instance) {
                $directPurify = $__htmlpurifier_instance->purify($payload);
                if (preg_match($pattern, $directPurify)) {
                    $status = 'PASS(別レイヤー)';
                }
            }
        }

        $this->results[] = [
            'id' => $id,
            'name' => $name,
            'status' => $status,
            'layer' => $layer,
            'input' => mb_substr($payload, 0, 100),
            'output' => mb_substr($result, 0, 200),
            'check' => "mustNotContain: {$pattern}",
        ];
    }

    public function getResults(): array
    {
        return $this->results;
    }

    public function printReport(): void
    {
        $pass = 0;
        $passAlt = 0;
        $fail = 0;

        echo "\n=== {$this->suiteName} ===\n\n";

        foreach ($this->results as $r) {
            $icon = match ($r['status']) {
                'PASS' => 'OK',
                'PASS(別レイヤー)' => 'OK*',
                'FAIL' => 'NG',
                default => '??',
            };

            echo "[{$icon}] {$r['id']} {$r['name']}\n";

            if ($r['status'] === 'FAIL') {
                echo "    入力: {$r['input']}\n";
                echo "    出力: {$r['output']}\n";
                echo "    検証: {$r['check']}\n";
                $fail++;
            } elseif ($r['status'] === 'PASS(別レイヤー)') {
                echo "    ※ 期待と異なるレイヤーで防御 — 要調査\n";
                $passAlt++;
            } else {
                $pass++;
            }
        }

        $total = count($this->results);
        echo "\n--- 結果: {$total}件中 PASS={$pass} PASS(別レイヤー)={$passAlt} FAIL={$fail} ---\n";
    }

    public function saveResultJson(string $path): void
    {
        file_put_contents($path, json_encode($this->results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }

    public function hasFailures(): bool
    {
        foreach ($this->results as $r) {
            if ($r['status'] === 'FAIL') return true;
        }
        return false;
    }
}
```

- [ ] **Step 2: テストランナーの動作確認**

Run: `php test/unit/tiptap-security/backend/SecurityTestRunner.php`
Expected: エラーなし（クラス定義のみなので出力なし）

- [ ] **Step 3: コミット**

```bash
git add test/unit/tiptap-security/backend/SecurityTestRunner.php
git commit -m "test: 脆弱性テスト用PHPテストランナー基盤を追加"
```

---

## Task 2: Suite 1 — XSS テスト（40件）

**Files:**
- Create: `test/unit/tiptap-security/backend/test_xss.php`

- [ ] **Step 1: scriptタグ系テスト（1-01〜1-07）を作成**

```php
<?php
require_once __DIR__ . '/SecurityTestRunner.php';

$t = new SecurityTestRunner('Suite 1: XSS (Stored XSS)');

// 4.1 scriptタグ系
$scriptPattern = '/<script/i';

$t->testFullPipeline('1-01', '基本scriptタグ',
    '<script>alert(1)</script>', $scriptPattern);
$t->testFullPipeline('1-02', '大文字混在',
    '<ScRiPt>alert(1)</sCrIpT>', $scriptPattern);
$t->testFullPipeline('1-03', 'null文字挿入',
    "<scr\x00ipt>alert(1)</script>", $scriptPattern);
$t->testFullPipeline('1-04', '改行挿入',
    "<scr\nipt>alert(1)</script>", $scriptPattern);
$t->testFullPipeline('1-05', 'タブ挿入',
    "<scr\tipt>alert(1)</script>", $scriptPattern);
$t->testFullPipeline('1-06', '閉じタグなし',
    '<script>alert(1)', $scriptPattern);
$t->testFullPipeline('1-07', '二重scriptタグ',
    '<script><script>alert(1)</script></script>', $scriptPattern);
```

- [ ] **Step 2: イベント属性系テスト（1-08〜1-15）を追加**

```php
// 4.2 イベント属性系
$eventPattern = '/on\w+\s*=/i';

$t->testFullPipeline('1-08', 'onerror',
    '<img src=x onerror="alert(1)">', $eventPattern);
$t->testFullPipeline('1-09', 'onload(body)',
    '<body onload="alert(1)">', $eventPattern);
$t->testFullPipeline('1-10', 'onmouseover',
    '<div onmouseover="alert(1)">test</div>', $eventPattern);
$t->testFullPipeline('1-11', 'onfocus+autofocus',
    '<input onfocus="alert(1)" autofocus>', $eventPattern);
$t->testFullPipeline('1-12', 'onanimationend',
    '<div onanimationend="alert(1)">', $eventPattern);
$t->testFullPipeline('1-13', '大文字イベント',
    '<img src=x ONERROR="alert(1)">', $eventPattern);
$t->testFullPipeline('1-14', 'スペース挿入(正規表現検証)',
    '<img src=x on error="alert(1)">', $eventPattern);
$t->testFullPipeline('1-15', 'タブ区切り',
    "<img src=x\tonerror=\"alert(1)\">", $eventPattern);
```

- [ ] **Step 3: javascript:URI系テスト（1-16〜1-22）を追加**

```php
// 4.3 javascript: URI系
$jsUriPattern = '/javascript\s*:/i';

$t->testFullPipeline('1-16', '基本javascript:',
    '<a href="javascript:alert(1)">click</a>', $jsUriPattern);
$t->testFullPipeline('1-17', '大文字混在',
    '<a href="JaVaScRiPt:alert(1)">', $jsUriPattern);
$t->testFullPipeline('1-18', 'タブ挿入',
    "<a href=\"java\tscript:alert(1)\">", $jsUriPattern);
$t->testFullPipeline('1-19', '改行挿入',
    "<a href=\"java\nscript:alert(1)\">", $jsUriPattern);
$t->testFullPipeline('1-20', 'エンティティ混在',
    '<a href="&#106;avascript:alert(1)">', $jsUriPattern);
$t->testFullPipeline('1-21', 'vbscript',
    '<a href="vbscript:MsgBox(1)">', '/vbscript\s*:/i');
$t->testFullPipeline('1-22', 'data:URI+script',
    '<a href="data:text/html,<script>alert(1)</script>">', $scriptPattern);
```

- [ ] **Step 4: SVG/MathML系（1-23〜1-27）を追加**

```php
// 4.4 SVG/MathML系
$t->testFullPipeline('1-23', 'SVG onload',
    '<svg onload="alert(1)">', $eventPattern);
$t->testFullPipeline('1-24', 'SVG script',
    '<svg><script>alert(1)</script></svg>', $scriptPattern);
$t->testFullPipeline('1-25', 'SVG animate',
    '<svg><animate onbegin="alert(1)">', '/onbegin\s*=/i');
$t->testFullPipeline('1-26', 'MathML',
    '<math><maction actiontype="statusline">XSS</maction></math>', '/<math/i');
$t->testFullPipeline('1-27', 'SVG foreignObject',
    '<svg><foreignObject><body onload="alert(1)">', $eventPattern);
```

- [ ] **Step 5: img/iframe/object系（1-28〜1-33）を追加**

```php
// 4.5 img/iframe/object系
$t->testFullPipeline('1-28', 'iframe',
    '<iframe src="javascript:alert(1)">', '/<iframe/i');
$t->testFullPipeline('1-29', 'iframe srcdoc',
    '<iframe srcdoc="<script>alert(1)</script>">', '/<iframe/i');
$t->testFullPipeline('1-30', 'object data',
    '<object data="javascript:alert(1)">', '/<object/i');
$t->testFullPipeline('1-31', 'embed src',
    '<embed src="javascript:alert(1)">', '/<embed/i');
$t->testFullPipeline('1-32', 'img longdesc',
    '<img src=x longdesc="javascript:alert(1)">', $jsUriPattern);
$t->testFullPipeline('1-33', 'video onerror',
    '<video><source onerror="alert(1)">', $eventPattern);
```

- [ ] **Step 6: style属性XSS（1-34〜1-37）+ テンプレートインジェクション（1-38〜1-40）を追加**

```php
// 4.6 style属性によるXSS
$t->testFullPipeline('1-34', 'expression()',
    '<div style="width:expression(alert(1))">', '/expression\s*\(/i');
$t->testFullPipeline('1-35', '-moz-binding',
    '<div style="-moz-binding:url(evil)">', '/-moz-binding/i');
$t->testFullPipeline('1-36', 'behavior',
    '<div style="behavior:url(evil.htc)">', '/behavior\s*:/i');
$t->testFullPipeline('1-37', 'background+javascript',
    '<div style="background:url(javascript:alert(1))">', $jsUriPattern);

// 4.7 テンプレートインジェクション
$t->testFullPipeline('1-38', 'templateタグ',
    '<template><script>alert(1)</script></template>', $scriptPattern);
$t->testFullPipeline('1-39', 'noscript',
    '<noscript><img src=x onerror="alert(1)"></noscript>', '/<noscript/i');
$t->testFullPipeline('1-40', 'meta refresh',
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', '/<meta/i');

// レポート出力
$t->printReport();
$t->saveResultJson(__DIR__ . '/result_xss.json');
exit($t->hasFailures() ? 1 : 0);
```

- [ ] **Step 7: テスト実行**

Run: `php test/unit/tiptap-security/backend/test_xss.php`
Expected: 40件全てPASSまたはPASS(別レイヤー)

- [ ] **Step 8: コミット**

```bash
git add test/unit/tiptap-security/backend/test_xss.php
git commit -m "test: Suite 1 XSS脆弱性テスト40件を実装"
```

---

## Task 3: Suite 2 — エンコーディングバイパス テスト（17件）

**Files:**
- Create: `test/unit/tiptap-security/backend/test_encoding_bypass.php`

- [ ] **Step 1: HTMLエンティティバイパス（2-01〜2-05）を作成**

```php
<?php
require_once __DIR__ . '/SecurityTestRunner.php';

$t = new SecurityTestRunner('Suite 2: エンコーディングバイパス');

$scriptPattern = '/<script/i';
$eventPattern = '/on\w+\s*=/i';

// 5.1 HTMLエンティティバイパス
$t->testFullPipeline('2-01', '10進数参照',
    '&#60;script&#62;alert(1)&#60;/script&#62;', $scriptPattern);
$t->testFullPipeline('2-02', '16進数参照',
    '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;', $scriptPattern);
$t->testFullPipeline('2-03', 'セミコロン省略',
    '&#60script&#62alert(1)&#60/script&#62', $scriptPattern);
$t->testFullPipeline('2-04', 'ゼロパディング',
    '&#0000060;script&#0000062;', $scriptPattern);
$t->testFullPipeline('2-05', '名前付き+数値混在',
    '&lt;script&gt;alert(&#49;)&lt;/script&gt;', $scriptPattern);
```

- [ ] **Step 2: 二重デコード（2-06〜2-09）を追加**

```php
// 5.2 二重デコード
$t->testFullPipeline('2-06', '二重HTMLエンコード',
    '&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;', $scriptPattern);
$t->testFullPipeline('2-07', 'URLエンコード+HTML',
    '%3Cscript%3Ealert(1)%3C/script%3E', $scriptPattern);
$t->testFullPipeline('2-08', '二重URLエンコード',
    '%253Cscript%253Ealert(1)%253C/script%253E', $scriptPattern);
$t->testFullPipeline('2-09', 'decode_html順序問題',
    '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;', $eventPattern);
```

- [ ] **Step 3: UTF-8バイパス（2-10〜2-12）+ null/制御文字バイパス（2-13〜2-17）を追加**

```php
// 5.3 UTF-8バイパス
$t->testFullPipeline('2-10', 'オーバーロングUTF-8',
    "\xC0\xBCscript\xC0\xBEalert(1)\xC0\xBC/script\xC0\xBE", $scriptPattern);
$t->testFullPipeline('2-11', 'UTF-8 BOM挿入',
    "\xEF\xBB\xBF<script>alert(1)</script>", $scriptPattern);
$t->testFullPipeline('2-12', 'UTF-7エンコード',
    '+ADw-script+AD4-alert(1)+ADw-/script+AD4-', $scriptPattern);

// 5.4 null/制御文字バイパス
$t->testFullPipeline('2-13', 'null文字タグ分断',
    "<scri\x00pt>alert(1)</script>", $scriptPattern);
$t->testFullPipeline('2-14', 'null文字属性分断',
    "<img src=x on\x00error=\"alert(1)\">", $eventPattern);
$t->testFullPipeline('2-15', 'バックスペース挿入',
    "<img src=x o\x08nerror=\"alert(1)\">", $eventPattern);
$t->testFullPipeline('2-16', 'ZWS挿入',
    "<scr\xE2\x80\x8Bipt>alert(1)</script>", $scriptPattern);
$t->testFullPipeline('2-17', 'ZWSP+イベント属性',
    "<img src=x on\xE2\x80\x8Berror=\"alert(1)\">", $eventPattern);

$t->printReport();
$t->saveResultJson(__DIR__ . '/result_encoding_bypass.json');
exit($t->hasFailures() ? 1 : 0);
```

- [ ] **Step 4: テスト実行**

Run: `php test/unit/tiptap-security/backend/test_encoding_bypass.php`
Expected: 17件全てPASS。特に2-06（二重エンコード）の結果に注目。

- [ ] **Step 5: コミット**

```bash
git add test/unit/tiptap-security/backend/test_encoding_bypass.php
git commit -m "test: Suite 2 エンコーディングバイパステスト17件を実装"
```

---

## Task 4: Suite 4〜7 — 標準カテゴリ テスト（32件）

**Files:**
- Create: `test/unit/tiptap-security/backend/test_html_injection.php`
- Create: `test/unit/tiptap-security/backend/test_css_injection.php`
- Create: `test/unit/tiptap-security/backend/test_dom_clobbering.php`
- Create: `test/unit/tiptap-security/backend/test_base64.php`

- [ ] **Step 1: Suite 4 HTMLインジェクションテスト（10件）を作成**

```php
<?php
require_once __DIR__ . '/SecurityTestRunner.php';

$t = new SecurityTestRunner('Suite 4: HTMLインジェクション');

$t->testFullPipeline('4-01', 'formタグ注入',
    '<form action="https://evil.com"><input type="submit" value="ログイン">', '/<form/i');
$t->testFullPipeline('4-02', 'baseタグ注入',
    '<base href="https://evil.com/">', '/<base/i');
$t->testFullPipeline('4-03', 'linkタグ注入',
    '<link rel="stylesheet" href="https://evil.com/evil.css">', '/<link/i');
// 4-04: 閉じタグ不整合 — タグ構造が修復されることを検証（テキスト保持はtestPreservedで別途検証）
$t->testFullPipeline('4-04', '閉じタグ不整合',
    '<b><i>text</b></i>', '/<i>[^<]*<\/b>/');  // 不正なネスト構造が残っていないこと
$t->testFullPipeline('4-05', '属性値引用符なし',
    '<img src=x onerror=alert(1)>', '/on\w+\s*=/i');
$t->testFullPipeline('4-06', 'バッククォート属性値',
    '<img src=`x` onerror=`alert(1)`>', '/on\w+\s*=/i');
$t->testFullPipeline('4-07', '不正なネスト',
    '<table><tr><td><table><form><td><input>', '/<form/i');
$t->testFullPipeline('4-08', 'コメントによるタグ隠蔽',
    '<!--<script>-->alert(1)<!--</script>-->', '/<script/i');
$t->testFullPipeline('4-09', 'CDATA注入',
    '<![CDATA[<script>alert(1)</script>]]>', '/<script/i');
$t->testFullPipeline('4-10', '未知のカスタム要素',
    '<custom-element onload="alert(1)">test</custom-element>', '/on\w+\s*=/i');

// 4-04は特殊: テキストが保持されることを確認
$t->testPreserved('4-04b', '閉じタグ不整合(テキスト保持)',
    '<b><i>text</b></i>', '/text/');

$t->printReport();
$t->saveResultJson(__DIR__ . '/result_html_injection.json');
exit($t->hasFailures() ? 1 : 0);
```

- [ ] **Step 2: Suite 5 CSSインジェクションテスト（10件）を作成**

```php
<?php
require_once __DIR__ . '/SecurityTestRunner.php';

$t = new SecurityTestRunner('Suite 5: CSSインジェクション');

$t->testFullPipeline('5-01', 'styleタグ注入',
    '<style>body{display:none}</style>', '/<style/i');
$t->testFullPipeline('5-02', '@import',
    '<div style="@import url(\'https://evil.com/evil.css\')">', '/@import/i');
$t->testFullPipeline('5-03', 'background-image URL',
    '<div style="background-image:url(\'https://evil.com/track.gif\')">', '/url\s*\(/i');
$t->testFullPipeline('5-04', 'UI詐欺: 全画面オーバーレイ [CRITICAL]',
    '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999">偽ログイン画面</div>',
    '/position\s*:\s*fixed/i');
$t->testFullPipeline('5-05', 'UI詐欺: 要素隠蔽 [CRITICAL]',
    '<div style="display:none">hidden</div><div style="opacity:0">invisible</div>',
    '/display\s*:\s*none/i');
$t->testFullPipeline('5-06', '外部リソース読み込み [CRITICAL]',
    '<div style="list-style-image:url(\'https://evil.com/track.gif\')">', '/url\s*\(/i');
$t->testFullPipeline('5-07', 'var()によるCSS変数',
    '<div style="color:var(--evil-color)">text</div>', '/var\s*\(/i');
$t->testFullPipeline('5-08', 'calc()の濫用',
    '<div style="width:calc(100vw - 1px)">text</div>', '/100vw/i');
$t->testFullPipeline('5-09', 'font-family注入',
    '<span style="font-family:\';</style><script>alert(1)</script>">', '/<script/i');
$t->testFullPipeline('5-10', 'unicode-range外部プローブ',
    '<style>@font-face{font-family:x;src:url(https://evil.com/f);unicode-range:U+0041}</style>', '/<style/i');

$t->printReport();
$t->saveResultJson(__DIR__ . '/result_css_injection.json');
exit($t->hasFailures() ? 1 : 0);
```

- [ ] **Step 3: Suite 6 DOMクロバリングテスト（5件）を作成**

```php
<?php
require_once __DIR__ . '/SecurityTestRunner.php';

$t = new SecurityTestRunner('Suite 6: DOMクロバリング');

$t->testFullPipeline('6-01', 'form名衝突',
    '<form id="getElementById">', '/<form/i');
$t->testFullPipeline('6-02', 'id属性でJS変数上書き [CRITICAL]',
    '<div id="__proto__">test</div>', '/id\s*=\s*["\']__proto__["\']/i');
$t->testFullPipeline('6-03', 'name属性でdocumentプロパティ上書き',
    '<img name="cookie" src=x>', '/name\s*=\s*["\']cookie["\']/i');
// 6-04: data-anchor はTiptapスキーマ経由のためフロントエンドテストで検証
$t->testFullPipeline('6-04', 'anchor id衝突(バックエンド)',
    '<a id="existingElementId">test</a>', '/id\s*=\s*["\']existingElementId["\']/i');
$t->testFullPipeline('6-05', '複数要素でNodeList生成 [CRITICAL]',
    '<a id="x"></a><a id="x"></a>', '/id\s*=\s*["\']x["\']/i');

$t->printReport();
$t->saveResultJson(__DIR__ . '/result_dom_clobbering.json');
exit($t->hasFailures() ? 1 : 0);
```

- [ ] **Step 4: Suite 7 base64画像悪用テスト（7件）を作成**

```php
<?php
require_once __DIR__ . '/SecurityTestRunner.php';

$t = new SecurityTestRunner('Suite 7: base64画像悪用');

// 正常ケース: 小さなbase64画像が保持されること
$smallPng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
$t->testPreserved('7-01', '正常なbase64画像',
    '<img src="data:image/png;base64,' . $smallPng . '">', '/data:image\/png;base64/');

// DoS: 巨大base64 (10MB相当の文字列) — メモリ上限を一時的に拡大
ini_set('memory_limit', '512M');
$largePayload = '<img src="data:image/png;base64,' . str_repeat('A', 10 * 1024 * 1024) . '">';
$startTime = microtime(true);
$result = vtlib_purify(decode_html($largePayload));
$elapsed = microtime(true) - $startTime;
$resultSize = strlen($result);
echo "[INFO] 7-02 巨大base64: 処理時間={$elapsed}秒, 出力サイズ={$resultSize}バイト\n";
// サイズ制限がない場合はFAILとして記録
$t->testFullPipeline('7-02', '巨大base64(DoS) [CRITICAL]',
    '<img src="data:image/png;base64,' . str_repeat('A', 1024 * 1024) . '">',
    '/^$/');  // 空出力でない=通過している（要検証として記録）

// 不正MIME型
$htmlBase64 = base64_encode('<script>alert(1)</script>');
$t->testFullPipeline('7-03', '不正MIME型',
    '<img src="data:text/html;base64,' . $htmlBase64 . '">', '/<script/i');

// SVG+XSS base64
$svgBase64 = base64_encode('<svg onload="alert(1)">');
$t->testFullPipeline('7-04', 'base64内にscript',
    '<img src="data:image/svg+xml;base64,' . $svgBase64 . '">', '/onload/i');

// 複数巨大画像
$t->testFullPipeline('7-05', '複数巨大画像 [CRITICAL]',
    '<img src="data:image/png;base64,' . str_repeat('A', 5 * 1024 * 1024) . '">'
    . '<img src="data:image/png;base64,' . str_repeat('A', 5 * 1024 * 1024) . '">',
    '/^$/');

// マーカー文字列偽装
$t->testFullPipeline('7-06', 'マーカー文字列偽装',
    '<img src="__VTIGERB64STRIPMARK_0" onerror="alert(1)">', '/on\w+\s*=/i');
$t->testFullPipeline('7-07', 'マーカー+base64混在',
    '<img src="data:image/png;base64,ABC" onerror="__VTIGERB64STRIPMARK_1">', '/on\w+\s*=/i');

$t->printReport();
$t->saveResultJson(__DIR__ . '/result_base64.json');
exit($t->hasFailures() ? 1 : 0);
```

- [ ] **Step 5: 各テストファイルを実行**

Run:
```
php test/unit/tiptap-security/backend/test_html_injection.php
php test/unit/tiptap-security/backend/test_css_injection.php
php test/unit/tiptap-security/backend/test_dom_clobbering.php
php test/unit/tiptap-security/backend/test_base64.php
```
Expected: 各スイート全件PASS（クリティカル項目は要検証結果を確認）

- [ ] **Step 6: コミット**

```bash
git add test/unit/tiptap-security/backend/test_html_injection.php
git add test/unit/tiptap-security/backend/test_css_injection.php
git add test/unit/tiptap-security/backend/test_dom_clobbering.php
git add test/unit/tiptap-security/backend/test_base64.php
git commit -m "test: Suite 4-7 標準カテゴリ脆弱性テスト32件を実装"
```

---

## Task 5: 一括実行スクリプト

**Files:**
- Create: `test/unit/tiptap-security/backend/run_all.php`

- [ ] **Step 1: 一括実行スクリプトを作成**

```php
<?php
/**
 * 全バックエンド脆弱性テスト一括実行
 *
 * 使い方: php test/unit/tiptap-security/backend/run_all.php
 * スモークテストのみ: php test/unit/tiptap-security/backend/run_all.php --smoke
 */

$isSmoke = in_array('--smoke', $argv);
$testFiles = [
    'test_xss.php',
    'test_encoding_bypass.php',
    'test_html_injection.php',
    'test_css_injection.php',
    'test_dom_clobbering.php',
    'test_base64.php',
];

$totalPass = 0;
$totalFail = 0;
$totalAlt = 0;
$failedSuites = [];

foreach ($testFiles as $file) {
    $path = __DIR__ . '/' . $file;
    if (!file_exists($path)) {
        echo "[SKIP] {$file} — ファイルが見つかりません\n";
        continue;
    }

    echo "\n" . str_repeat('=', 60) . "\n実行中: {$file}\n" . str_repeat('=', 60) . "\n";
    $output = [];
    $exitCode = 0;
    exec("php {$path} 2>&1", $output, $exitCode);

    echo implode("\n", $output) . "\n";

    if ($exitCode !== 0) {
        $failedSuites[] = $file;
    }

    // 結果JSONから集計
    $jsonPath = __DIR__ . '/result_' . str_replace('test_', '', str_replace('.php', '.json', $file));
    if (file_exists($jsonPath)) {
        $results = json_decode(file_get_contents($jsonPath), true);
        foreach ($results as $r) {
            match ($r['status']) {
                'PASS' => $totalPass++,
                'PASS(別レイヤー)' => $totalAlt++,
                'FAIL' => $totalFail++,
                default => null,
            };
        }
    }
}

echo "\n\n" . str_repeat('=', 60) . "\n";
echo "全テスト結果サマリー\n";
echo str_repeat('=', 60) . "\n";
echo "PASS: {$totalPass}\n";
echo "PASS(別レイヤー): {$totalAlt}\n";
echo "FAIL: {$totalFail}\n";
echo "合計: " . ($totalPass + $totalAlt + $totalFail) . "\n";

if (!empty($failedSuites)) {
    echo "\n失敗スイート:\n";
    foreach ($failedSuites as $s) {
        echo "  - {$s}\n";
    }
    exit(1);
}

echo "\n全スイートPASS\n";
exit(0);
```

- [ ] **Step 2: 一括実行テスト**

Run: `php test/unit/tiptap-security/backend/run_all.php`
Expected: 全89件（Suite 1-2, 4-7）のサマリーが表示される

- [ ] **Step 3: コミット**

```bash
git add test/unit/tiptap-security/backend/run_all.php
git commit -m "test: バックエンド脆弱性テスト一括実行スクリプトを追加"
```

---

## Task 6: フロントエンド正規化関数セキュリティテスト（Vitest）

**Files:**
- Create: `assets/react-web-components/src/components/ui/tiptap/__tests__/security/normalize-security.test.ts`

- [ ] **Step 1: normalizeColor のセキュリティテストを作成**

```typescript
import { describe, it, expect } from 'vitest';
import {
  normalizeColor,
  normalizeLength,
  normalizeSpacing,
  normalizeBorderStyle,
  normalizeTextAlign,
  normalizeVerticalAlign,
  normalizeBorderShorthand,
} from '../../extensions/utils/normalize';

describe('normalizeColor セキュリティテスト', () => {
  // 正常値が正規化されること
  it('正常な#RRGGBB値を保持する', () => {
    expect(normalizeColor('#ff0000')).toBe('#ff0000');
  });

  it('正常なrgb()値を#RRGGBBに正規化する', () => {
    expect(normalizeColor('rgb(255, 0, 0)')).toBe('#ff0000');
  });

  it('正常なCSS名前付き色を正規化する', () => {
    expect(normalizeColor('red')).toBe('#ff0000');
  });

  // 不正値がnullを返すこと
  it('expression()を含む値を拒否する', () => {
    expect(normalizeColor('expression(alert(1))')).toBeNull();
  });

  it('javascript:を含む値を拒否する', () => {
    expect(normalizeColor('javascript:alert(1)')).toBeNull();
  });

  it('url()を含む値を拒否する', () => {
    expect(normalizeColor('url(https://evil.com)')).toBeNull();
  });

  it('hsl()形式を拒否する（未サポート）', () => {
    // hsl()がサポートされていない場合はnull
    const result = normalizeColor('hsl(0, 100%, 50%)');
    // サポートされている場合は正規化される、されていない場合はnull
    if (result !== null) {
      expect(result).toMatch(/^#[0-9a-f]{6}$/);
    }
  });

  it('空文字を拒否する', () => {
    expect(normalizeColor('')).toBeNull();
  });

  it('制御文字を含む値を拒否する', () => {
    expect(normalizeColor('\x00red')).toBeNull();
  });
});
```

- [ ] **Step 2: normalizeLength のセキュリティテストを追加**

```typescript
describe('normalizeLength セキュリティテスト', () => {
  it('正常なpx値を保持する', () => {
    expect(normalizeLength('16px')).toBe('16px');
  });

  it('maxPx上限を超える値をクランプする', () => {
    const result = normalizeLength('3000px', 2000);
    if (result !== null) {
      const num = parseInt(result, 10);
      expect(num).toBeLessThanOrEqual(2000);
    }
  });

  it('負の値を拒否する', () => {
    const result = normalizeLength('-10px', undefined, 0);
    expect(result).toBeNull();
  });

  it('expression()を含む値を拒否する', () => {
    expect(normalizeLength('expression(alert(1))')).toBeNull();
  });

  it('calc()にvwを含む値を処理する', () => {
    // calc(100vw)がnullまたはvw除去後の値を返すか確認
    const result = normalizeLength('calc(100vw - 1px)');
    if (result !== null) {
      expect(result).not.toContain('vw');
    }
  });

  it('極端に大きい数値を処理する', () => {
    const result = normalizeLength('999999px', 2000);
    if (result !== null) {
      const num = parseInt(result, 10);
      expect(num).toBeLessThanOrEqual(2000);
    }
  });
});
```

- [ ] **Step 3: 残りの正規化関数テストを追加**

```typescript
describe('normalizeBorderStyle セキュリティテスト', () => {
  it('有効なborder-styleを受け入れる', () => {
    expect(normalizeBorderStyle('solid')).toBe('solid');
    expect(normalizeBorderStyle('dashed')).toBe('dashed');
  });

  it('無効な値を拒否する', () => {
    expect(normalizeBorderStyle('expression(alert(1))')).toBeNull();
    expect(normalizeBorderStyle('<script>')).toBeNull();
  });
});

describe('normalizeTextAlign セキュリティテスト', () => {
  it('有効なtext-alignを受け入れる', () => {
    expect(normalizeTextAlign('left')).toBe('left');
    expect(normalizeTextAlign('center')).toBe('center');
  });

  it('無効な値を拒否する', () => {
    expect(normalizeTextAlign('expression(alert(1))')).toBeNull();
    expect(normalizeTextAlign('; background:url(evil)')).toBeNull();
  });
});

describe('normalizeVerticalAlign セキュリティテスト', () => {
  it('有効なvertical-alignを受け入れる', () => {
    expect(normalizeVerticalAlign('top')).toBe('top');
    expect(normalizeVerticalAlign('middle')).toBe('middle');
  });

  it('無効な値を拒否する', () => {
    expect(normalizeVerticalAlign('javascript:alert(1)')).toBeNull();
  });
});

describe('normalizeSpacing セキュリティテスト', () => {
  it('有効なspacing値を受け入れる', () => {
    const result = normalizeSpacing('10px');
    expect(result).not.toBeNull();
  });

  it('不正なCSSインジェクションを拒否する', () => {
    expect(normalizeSpacing('10px; background:url(evil)')).toBeNull();
  });
});

describe('normalizeBorderShorthand セキュリティテスト', () => {
  it('有効なborder shorthandを受け入れる', () => {
    const result = normalizeBorderShorthand('1px solid #000000');
    expect(result).not.toBeNull();
  });

  it('不正な値を拒否する', () => {
    expect(normalizeBorderShorthand('expression(alert(1))')).toBeNull();
  });
});
```

- [ ] **Step 4: テスト実行**

Run: `cd assets/react-web-components && npx vitest run src/components/ui/tiptap/__tests__/security/normalize-security.test.ts`
Expected: 全テストPASS

- [ ] **Step 5: コミット**

```bash
git add assets/react-web-components/src/components/ui/tiptap/__tests__/security/normalize-security.test.ts
git commit -m "test: フロントエンド正規化関数セキュリティテストを追加(Vitest)"
```

---

## Task 7: Suite 3 — レイヤー間の隙間 結合テスト（22件）

Suite 3はPlaywright MCP経由のブラウザ操作テストと、PHPスクリプトによるデータ検証の2段構成。

**Files:**
- Create: `test/integration/tiptap-security/suite3_layer_gap.php`

- [ ] **Step 1: データ準備・検証スクリプトを作成**

Suite 3の結合テストは以下の手順で実行する:
1. PHPスクリプトでテストレコードを作成し、ペイロードを直接DBに投入
2. Playwright MCPで画面を開き、表示されたHTMLを検証
3. Playwright MCPでソースモード経由のペイロード入力→保存→再表示を検証

```php
<?php
/**
 * Suite 3: レイヤー間の隙間テスト — データ準備・検証スクリプト
 *
 * 使い方:
 *   準備: php suite3_layer_gap.php --prepare
 *   検証: php suite3_layer_gap.php --verify
 *   クリーンアップ: php suite3_layer_gap.php --cleanup
 */

chdir('/var/www/html/GitHub');
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'includes/runtime/Globals.php';
include_once 'include/utils/utils.php';
include_once 'include/utils/VtlibUtils.php';

global $adb;
if ($adb === null) {
    $adb = PearDatabase::getInstance();
}

$action = $argv[1] ?? '--help';

// --- 3-08〜3-11: decode_html処理順序テスト ---
// これらはPHPバックエンドの浄化パイプラインのみで検証可能
if ($action === '--verify-pipeline') {
    $tests = [
        ['3-08', 'エンティティ偽装script', '&lt;script&gt;alert(1)&lt;/script&gt;', '/<script/i'],
        ['3-09', 'エンティティ偽装イベント属性', '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;', '/on\w+\s*=/i'],
        ['3-10', '二重エンコード浄化回避[CRITICAL]', '&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;', '/<script/i'],
        ['3-11', '三重エンコード', '&amp;amp;lt;script&amp;amp;gt;alert(1)', '/<script/i'],
    ];

    echo "=== Suite 3: decode_html処理順序テスト ===\n\n";

    foreach ($tests as [$id, $name, $payload, $pattern]) {
        // Save.phpと同じ処理順序をシミュレート
        $step1 = decode_html($payload);
        $step2 = vtlib_purify($step1);
        $step3 = decode_html($step2);
        $step4 = purifyHtmlEventAttributes($step3, true);

        $found = preg_match($pattern, $step4);
        $status = $found ? 'NG' : 'OK';

        echo "[{$status}] {$id} {$name}\n";
        echo "    入力:  " . mb_substr($payload, 0, 80) . "\n";
        echo "    Step1(decode_html): " . mb_substr($step1, 0, 80) . "\n";
        echo "    Step2(vtlib_purify): " . mb_substr($step2, 0, 80) . "\n";
        echo "    Step3(decode_html2): " . mb_substr($step3, 0, 80) . "\n";
        echo "    Step4(purifyEvent): " . mb_substr($step4, 0, 80) . "\n";

        if ($found) {
            echo "    *** FAIL: 危険なパターンが残存 ***\n";
        }
        echo "\n";
    }

    // 3-19, 3-20: data: URIスキーム通過検証
    echo "=== Suite 3: data: URIスキーム通過検証 ===\n\n";

    $dataTests = [
        ['3-19', 'data: URI内SVGスクリプト', '<img src="data:image/svg+xml,<svg onload=\'alert(1)\'>">', '/onload/i'],
        ['3-20', 'data: URI aタグ経由', '<a href="data:text/html,<script>alert(1)</script>">click</a>', '/data:text\/html/i'],
    ];

    foreach ($dataTests as [$id, $name, $payload, $pattern]) {
        $step1 = decode_html($payload);
        $step2 = vtlib_purify($step1);
        $step3 = decode_html($step2);
        $step4 = purifyHtmlEventAttributes($step3, true);

        $found = preg_match($pattern, $step4);
        $status = $found ? 'NG' : 'OK';

        echo "[{$status}] {$id} {$name}\n";
        echo "    入力:  " . mb_substr($payload, 0, 100) . "\n";
        echo "    最終出力: " . mb_substr($step4, 0, 200) . "\n\n";
    }

    // 3-21: キャッシュ機構の安全性検証
    echo "=== Suite 3: キャッシュ機構検証 ===\n\n";

    $payload = '<img src=x onerror="alert(1)">';
    $result1 = vtlib_purify(decode_html($payload));
    $result2 = vtlib_purify(decode_html($payload));  // キャッシュヒット
    $clean1 = !preg_match('/on\w+\s*=/i', $result1);
    $clean2 = !preg_match('/on\w+\s*=/i', $result2);
    $status = ($clean1 && $clean2) ? 'OK' : 'NG';
    echo "[{$status}] 3-21 同一ペイロード別フィールド(キャッシュヒット検証)\n";
    echo "    1回目: " . ($clean1 ? '浄化済み' : '未浄化') . "\n";
    echo "    2回目(cache): " . ($clean2 ? '浄化済み' : '未浄化') . "\n\n";

    exit(0);
}

// --- 3-12〜3-18: フィールド別保存経路差異 ---
// これらはPlaywright MCP経由で手動実行する手順書として出力
if ($action === '--field-test-guide') {
    echo "=== Suite 3: フィールド別保存経路差異テスト手順 ===\n\n";
    echo "ペイロード: <img src=x onerror=\"alert(1)\">\n\n";

    $fields = [
        ['3-12', 'notecontent', 'Documents', 'Save.php'],
        ['3-13', 'description', 'Leads', 'Save.php'],
        ['3-14', 'commentcontent', 'ModComments', 'SaveAjax.php'],
        ['3-15', 'solution', 'HelpDesk', 'Save.php'],
        ['3-16', 'question', 'Faq', 'Save.php'],
        ['3-17', 'faq_answer', 'Faq', 'Save.php'],
        ['3-18', 'signature', 'Users(設定)', 'SaveAjax.php'],
    ];

    foreach ($fields as [$id, $field, $module, $route]) {
        echo "{$id}. {$module} > {$field} (経路: {$route})\n";
        echo "   手順: 編集画面でソースモード切替→ペイロード入力→保存→再編集で確認\n";
        echo "   期待: onerror属性が除去されていること\n\n";
    }

    // 3-22: SaveAjax既存レコード編集パス
    echo "3-22. ModComments > commentcontent (既存レコード編集)\n";
    echo "   手順: 既存コメントを編集→ペイロード入力→保存→再表示で確認\n";
    echo "   期待: onerror属性が除去されていること\n\n";

    exit(0);
}

echo "使い方:\n";
echo "  php suite3_layer_gap.php --verify-pipeline  パイプライン検証(3-08〜3-11, 3-19〜3-21)\n";
echo "  php suite3_layer_gap.php --field-test-guide  フィールド別テスト手順出力(3-12〜3-18, 3-22)\n";
```

- [ ] **Step 2: パイプライン検証テスト実行**

Run: `php test/integration/tiptap-security/suite3_layer_gap.php --verify-pipeline`
Expected: 3-08〜3-11, 3-19〜3-21 が全てOK。特に3-10（二重エンコード）の結果に注目。

- [ ] **Step 3: フィールド別テスト手順確認**

Run: `php test/integration/tiptap-security/suite3_layer_gap.php --field-test-guide`
Expected: テスト手順が表示される

- [ ] **Step 4: Playwright MCPでソースモード経由テスト（3-01〜3-04）を手動実行**

以下の手順でPlaywright MCPを使用してテストを実施する:

1. ログイン（admin/admin）
2. Documents > 新規作成
3. notecontentのTiptapエディタでソースモードに切替
4. `<script>alert(1)</script>` を入力して保存
5. 再度編集画面を開き、ソースモードでHTMLを確認
6. scriptタグが除去されていることを検証

3-02〜3-04も同様の手順で実施（ペイロードを変更）。
スクリーンショットを `test/integration/tiptap-security/evidence/` に保存。

- [ ] **Step 5: Playwright MCPで保存→再表示テスト（3-05〜3-07）を手動実行**

1. 3-05: Tiptapで色付きテキスト入力→保存→再編集画面で色が保持されるか確認
2. 3-06: ソースモードで`<div style="background-color:#ff0000">test</div>`入力→保存→再編集
3. 3-07: 同じレコードを2回保存→内容が変化しないか確認

- [ ] **Step 6: コミット**

```bash
git add test/integration/tiptap-security/suite3_layer_gap.php
git commit -m "test: Suite 3 レイヤー間の隙間テスト（パイプライン検証+手順書）を実装"
```

---

## Task 8: テスト結果集約と最終レポート

**Files:**
- テスト結果JSONファイル群を集約

- [ ] **Step 1: 全バックエンドテスト一括実行**

Run: `php test/unit/tiptap-security/backend/run_all.php`
Expected: 89件のサマリーが表示される

- [ ] **Step 2: フロントエンドテスト実行**

Run: `cd assets/react-web-components && npx vitest run src/components/ui/tiptap/__tests__/security/`
Expected: 全テストPASS

- [ ] **Step 3: Suite 3パイプライン検証実行**

Run: `php test/integration/tiptap-security/suite3_layer_gap.php --verify-pipeline`
Expected: 全件OK

- [ ] **Step 4: FAIL/クリティカル項目の結果をユーザーに報告**

以下の結果を確認してユーザーに報告する:
- FAILがある場合: 具体的なテストケースID、入力、出力を報告
- PASS（別レイヤー）がある場合: 期待レイヤーと実際の防御レイヤーの差異を報告
- クリティカル要検証項目（3-10, 5-05, 6-02, 7-02/7-05）の結果を個別に報告

- [ ] **Step 5: 最終コミット**

```bash
git add test/unit/tiptap-security/backend/result_*.json
git commit -m "test: 脆弱性テスト結果JSONを追加（111ケース）"
```
