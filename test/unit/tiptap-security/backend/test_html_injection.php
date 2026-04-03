<?php
/**
 * Suite 4: HTMLインジェクション テスト — 10件
 *
 * 使い方: php test/unit/tiptap-security/backend/test_html_injection.php
 */
require_once __DIR__ . '/SecurityTestRunner.php';

$runner = new SecurityTestRunner();

// === Suite 4: HTMLインジェクション (4-01〜4-10) ===
$runner->addCase('4-01', '<form action="https://evil.com"><input type="submit" value="ログイン">', 'html_injection', 'REMOVED');
$runner->addCase('4-02', '<base href="https://evil.com/">', 'html_injection', 'REMOVED');
$runner->addCase('4-03', '<link rel="stylesheet" href="https://evil.com/evil.css">', 'html_injection', 'REMOVED');
// 4-04: 閉じタグ不整合 — テキスト保持を確認
$runner->addCase('4-04', '<b><i>text</b></i>', 'preservation', 'PRESERVED', '/text/');
$runner->addCase('4-05', '<img src=x onerror=alert(1)>', 'html_injection', 'REMOVED');
$runner->addCase('4-06', '<img src=`x` onerror=`alert(1)`>', 'html_injection', 'REMOVED');
$runner->addCase('4-07', '<table><tr><td><table><form><td><input>', 'html_injection', 'REMOVED');
$runner->addCase('4-08', '<!--<script>-->alert(1)<!--</script>-->', 'html_injection', 'REMOVED');
$runner->addCase('4-09', '<![CDATA[<script>alert(1)</script>]]>', 'html_injection', 'REMOVED');
$runner->addCase('4-10', '<custom-element onload="alert(1)">test</custom-element>', 'html_injection', 'REMOVED');

// テスト実行
$runner->testFullPipeline();
$runner->testPreserved();
$runner->printReport();
$runner->saveResultJson(__DIR__ . '/result_html_injection.json');
exit($runner->hasFailures() ? 1 : 0);
