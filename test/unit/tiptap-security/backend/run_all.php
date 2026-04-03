<?php
/**
 * 全バックエンド脆弱性テスト一括実行
 *
 * 使い方:
 *   php test/unit/tiptap-security/backend/run_all.php
 *   php test/unit/tiptap-security/backend/run_all.php --smoke  (スモークテストのみ)
 */

$testFiles = [
    'test_xss.php',
    'test_encoding_bypass.php',
    'test_html_injection.php',
    'test_css_injection.php',
    'test_dom_clobbering.php',
    'test_base64.php',
];

$failedSuites = [];
$allOutput = [];

echo str_repeat('=', 60) . "\n";
echo "  Tiptap Security Test - 全スイート一括実行\n";
echo str_repeat('=', 60) . "\n\n";

foreach ($testFiles as $file) {
    $path = __DIR__ . '/' . $file;
    if (!file_exists($path)) {
        echo "[SKIP] {$file} — ファイルが見つかりません\n";
        continue;
    }

    echo str_repeat('-', 60) . "\n";
    echo "実行中: {$file}\n";
    echo str_repeat('-', 60) . "\n";

    $output = [];
    $exitCode = 0;
    exec("php " . escapeshellarg($path) . " 2>&1", $output, $exitCode);

    echo implode("\n", $output) . "\n";
    $allOutput[$file] = $output;

    if ($exitCode !== 0) {
        $failedSuites[] = $file;
    }
}

// 結果JSONから集計
$totalOk = 0;
$totalOkAlt = 0;
$totalNg = 0;
$totalSkip = 0;

$resultFiles = glob(__DIR__ . '/result_*.json');
foreach ($resultFiles as $jsonPath) {
    $data = json_decode(file_get_contents($jsonPath), true);
    if (isset($data['summary'])) {
        $totalOk    += $data['summary']['ok'] ?? 0;
        $totalOkAlt += $data['summary']['ok_partial'] ?? 0;
        $totalNg    += $data['summary']['ng'] ?? 0;
        $totalSkip  += $data['summary']['skip'] ?? 0;
    }
}

$total = $totalOk + $totalOkAlt + $totalNg + $totalSkip;

echo "\n\n" . str_repeat('=', 60) . "\n";
echo "  全テスト結果サマリー\n";
echo str_repeat('=', 60) . "\n";
echo "  OK:   {$totalOk}\n";
echo "  OK*:  {$totalOkAlt}\n";
echo "  NG:   {$totalNg}\n";
echo "  SKIP: {$totalSkip}\n";
echo "  合計: {$total}\n";

if (!empty($failedSuites)) {
    echo "\n  失敗スイート:\n";
    foreach ($failedSuites as $s) {
        echo "    - {$s}\n";
    }
    echo str_repeat('=', 60) . "\n";
    exit(1);
}

echo "\n  全スイートPASS\n";
echo str_repeat('=', 60) . "\n";
exit(0);
