<?php
/**
 * Suite 7: base64画像悪用 テスト — 7件
 *
 * 使い方: php test/unit/tiptap-security/backend/test_base64.php
 */
ini_set('memory_limit', '512M');
require_once __DIR__ . '/SecurityTestRunner.php';

$runner = new SecurityTestRunner();

// 7-01: 正常なbase64画像 — 保持されること
$smallPng = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
$runner->addCase('7-01', '<img src="data:image/png;base64,' . $smallPng . '">', 'preservation', 'PRESERVED', '/data:image\/png;base64/');

// 7-02: 巨大base64 — 512KBで実行可能サイズに設定しDoS耐性を検証
// SecurityTestRunnerの1MB制限内で最大限のペイロードを投入
$runner->addCase('7-02', '<img src="data:image/png;base64,' . str_repeat('A', 524288) . '">', 'base64', 'REMOVED');

// 7-03: 不正MIME型 (text/html)
$htmlBase64 = base64_encode('<script>alert(1)</script>');
$runner->addCase('7-03', '<img src="data:text/html;base64,' . $htmlBase64 . '">', 'base64', 'REMOVED');

// 7-04: base64内にSVG+onload
$svgBase64 = base64_encode('<svg onload="alert(1)">');
$runner->addCase('7-04', '<img src="data:image/svg+xml;base64,' . $svgBase64 . '">', 'base64', 'REMOVED');

// 7-05: 複数巨大画像 — 各256KBで合計512KB
$runner->addCase('7-05', '<img src="data:image/png;base64,' . str_repeat('A', 262144) . '"><img src="data:image/png;base64,' . str_repeat('A', 262144) . '">', 'base64', 'REMOVED');

// 7-06: マーカー文字列偽装
$runner->addCase('7-06', '<img src="__VTIGERB64STRIPMARK_0" onerror="alert(1)">', 'base64', 'REMOVED');

// 7-07: マーカー+base64混在
$runner->addCase('7-07', '<img src="data:image/png;base64,ABC" onerror="__VTIGERB64STRIPMARK_1">', 'base64', 'REMOVED');

// テスト実行
$runner->testFullPipeline();
$runner->testPreserved();
$runner->printReport();
$runner->saveResultJson(__DIR__ . '/result_base64.json');
exit($runner->hasFailures() ? 1 : 0);
