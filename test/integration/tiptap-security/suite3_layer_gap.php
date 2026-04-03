<?php
/**
 * Suite 3: レイヤー間の隙間テスト
 *
 * 使い方:
 *   php test/integration/tiptap-security/suite3_layer_gap.php --verify-pipeline
 *   php test/integration/tiptap-security/suite3_layer_gap.php --field-test-guide
 */

chdir('/var/www/html/GitHub');
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'includes/runtime/Globals.php';
include_once 'include/utils/utils.php';
include_once 'include/utils/VtlibUtils.php';

$action = $argv[1] ?? '--help';

/**
 * Save.phpと同じ浄化パイプラインを再現して各ステップを表示
 */
function runPipelineTest(string $id, string $name, string $payload, string $dangerPattern): bool
{
    $step1 = decode_html($payload);
    $step2 = vtlib_purify($step1);
    $step3 = decode_html($step2);
    $step4 = purifyHtmlEventAttributes($step3, true);

    $found = preg_match($dangerPattern, $step4);
    $status = $found ? 'NG' : 'OK';

    echo "[{$status}] {$id} {$name}\n";
    echo "    入力:           " . mb_substr($payload, 0, 80) . "\n";
    echo "    Step1(decode):  " . mb_substr($step1, 0, 80) . "\n";
    echo "    Step2(purify):  " . mb_substr($step2, 0, 80) . "\n";
    echo "    Step3(decode2): " . mb_substr($step3, 0, 80) . "\n";
    echo "    Step4(event):   " . mb_substr($step4, 0, 80) . "\n";

    if ($found) {
        echo "    *** FAIL: 危険なパターンが残存 ***\n";
    }
    echo "\n";

    return !$found;
}

// --- パイプライン検証 ---
if ($action === '--verify-pipeline') {
    $allPassed = true;
    $scriptPattern = '/<script/i';
    $eventPattern = '/on\w+\s*=/i';

    // === 6.3 decode_html処理順序 (3-08〜3-11) ===
    echo "=== 6.3 decode_html処理順序テスト ===\n\n";

    $allPassed &= runPipelineTest('3-08', 'エンティティ偽装script',
        '&lt;script&gt;alert(1)&lt;/script&gt;', $scriptPattern);
    $allPassed &= runPipelineTest('3-09', 'エンティティ偽装イベント属性',
        '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;', $eventPattern);
    $allPassed &= runPipelineTest('3-10', '二重エンコード浄化回避[CRITICAL]',
        '&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;', $scriptPattern);
    $allPassed &= runPipelineTest('3-11', '三重エンコード',
        '&amp;amp;lt;script&amp;amp;gt;alert(1)', $scriptPattern);

    // === 6.5 data: URIスキーム通過検証 (3-19〜3-20) ===
    echo "=== 6.5 data: URIスキーム通過検証 ===\n\n";

    $allPassed &= runPipelineTest('3-19', 'data: URI内SVGスクリプト[CRITICAL]',
        '<img src="data:image/svg+xml,<svg onload=\'alert(1)\'>">', '/onload/i');
    $allPassed &= runPipelineTest('3-20', 'data: URI aタグ経由[CRITICAL]',
        '<a href="data:text/html,<script>alert(1)</script>">click</a>', '/data:text\/html/i');

    // === 6.6 キャッシュ機構の安全性検証 (3-21) ===
    echo "=== 6.6 キャッシュ機構検証 ===\n\n";

    $payload = '<img src=x onerror="alert(1)">';
    $result1 = vtlib_purify(decode_html($payload));
    $result2 = vtlib_purify(decode_html($payload));  // キャッシュヒット
    $clean1 = !preg_match('/on\w+\s*=/i', $result1);
    $clean2 = !preg_match('/on\w+\s*=/i', $result2);
    $status = ($clean1 && $clean2) ? 'OK' : 'NG';
    echo "[{$status}] 3-21 同一ペイロード別フィールド(キャッシュヒット検証)\n";
    echo "    1回目: " . ($clean1 ? '浄化済み' : '未浄化') . "\n";
    echo "    2回目(cache): " . ($clean2 ? '浄化済み' : '未浄化') . "\n\n";
    $allPassed &= ($clean1 && $clean2);

    // === サマリー ===
    echo str_repeat('=', 60) . "\n";
    echo "  パイプライン検証: " . ($allPassed ? "全件OK" : "NG あり") . "\n";
    echo str_repeat('=', 60) . "\n";

    exit($allPassed ? 0 : 1);
}

// --- フィールド別テスト手順 ---
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
        echo "   手順: 編集画面→ソースモード切替→ペイロード入力→保存→再編集で確認\n";
        echo "   期待: onerror属性が除去されていること\n\n";
    }

    echo "3-22. ModComments > commentcontent (既存レコード編集)\n";
    echo "   手順: 既存コメント編集→ペイロード入力→保存→再表示で確認\n";
    echo "   期待: onerror属性が除去されていること\n\n";

    echo "=== ソースモード経由テスト (3-01〜3-04) ===\n\n";
    echo "3-01. ソースモードでscript注入: <script>alert(1)</script>\n";
    echo "3-02. ソースモードでイベント属性: <img src=x onerror=\"alert(1)\">\n";
    echo "3-03. ソースモードでjavascript:URI: <a href=\"javascript:alert(1)\">link</a>\n";
    echo "3-04. ソースモードでiframe: <iframe src=\"https://evil.com\">\n\n";

    echo "=== 保存→再表示テスト (3-05〜3-07) ===\n\n";
    echo "3-05. 色付きテキスト入力→保存→再編集→色保持確認\n";
    echo "3-06. ソースモードで<div style=\"background-color:#ff0000\">→保存→再編集\n";
    echo "3-07. 同じレコードを2回保存→内容不変確認\n\n";

    exit(0);
}

echo "使い方:\n";
echo "  php suite3_layer_gap.php --verify-pipeline  パイプライン検証(3-08〜3-11, 3-19〜3-21)\n";
echo "  php suite3_layer_gap.php --field-test-guide  フィールド別テスト手順出力\n";
