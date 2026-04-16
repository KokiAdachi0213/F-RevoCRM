<?php
/**
 * HTMLPurifier_URIFilter_DataImageOnly テスト
 *
 * vtlib_purify() が data: URI を正しく処理することを検証する。
 * - data:text/html → 除去される（XSS防御）
 * - data:image/png;base64,... → 保持される（正当な画像）
 */

chdir('/var/www/html/github');
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'vtlib/Vtiger/Functions.php';
require_once 'include/utils/VtlibUtils.php';

$pass = 0;
$fail = 0;

function assert_contains($label, $haystack, $needle) {
    global $pass, $fail;
    if (strpos($haystack, $needle) !== false) {
        echo "[PASS] $label\n";
        $pass++;
    } else {
        echo "[FAIL] $label\n  期待: '$needle' を含む\n  実際: $haystack\n";
        $fail++;
    }
}

function assert_not_contains($label, $haystack, $needle) {
    global $pass, $fail;
    if (strpos($haystack, $needle) === false) {
        echo "[PASS] $label\n";
        $pass++;
    } else {
        echo "[FAIL] $label\n  期待: '$needle' を含まない\n  実際: $haystack\n";
        $fail++;
    }
}

// テスト1: data:text/html は除去される
$input1 = '<a href="data:text/html,<script>alert(1)</script>">テスト</a>';
$result1 = vtlib_purify($input1);
assert_not_contains('data:text/html URI は除去される', $result1, 'data:text/html');

// テスト2: data:image/png;base64 は保持される（正当な画像）
$pngBase64 = base64_encode("\x89PNG\r\n\x1a\n" . str_repeat("\x00", 20));
$input2 = '<img src="data:image/png;base64,' . $pngBase64 . '">';
$result2 = vtlib_purify($input2);
assert_contains('data:image/png;base64 URI は保持される', $result2, 'data:image/png;base64');

// テスト3: data:image/jpeg は保持される
$jpegBase64 = base64_encode("\xFF\xD8\xFF" . str_repeat("\x00", 20));
$input3 = '<img src="data:image/jpeg;base64,' . $jpegBase64 . '">';
$result3 = vtlib_purify($input3);
assert_contains('data:image/jpeg;base64 URI は保持される', $result3, 'data:image/jpeg;base64');

// テスト4: data:application/javascript は除去される
$input4 = '<img src="data:application/javascript,alert(1)">';
$result4 = vtlib_purify($input4);
assert_not_contains('data:application/javascript URI は除去される', $result4, 'data:application/javascript');

echo "\n結果: {$pass}件PASS / {$fail}件FAIL\n";
exit($fail > 0 ? 1 : 0);
