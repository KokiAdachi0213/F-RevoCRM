<?php
/**
 * Suite 6: DOMクロバリング テスト — 5件
 *
 * 使い方: php test/unit/tiptap-security/backend/test_dom_clobbering.php
 */
require_once __DIR__ . '/SecurityTestRunner.php';

$runner = new SecurityTestRunner();

// === Suite 6: DOMクロバリング (6-01〜6-05) ===
$runner->addCase('6-01', '<form id="getElementById">', 'dom_clobbering', 'REMOVED');
$runner->addCase('6-02', '<div id="__proto__">test</div>', 'dom_clobbering', 'REMOVED');
$runner->addCase('6-03', '<img name="cookie" src=x>', 'dom_clobbering', 'REMOVED');
// 6-04: data-anchor属性がid/name属性に変換されないことを検証
// HTMLPurifierはdata-colorのみ許可するため、data-anchorは除去される
// 重要なのは「id属性として残らない」こと（DOMクロバリング防止）
$runner->addCase('6-04', '<a data-anchor="existingElementId">test</a>', 'dom_clobbering', 'REMOVED');
$runner->addCase('6-05', '<a id="x"></a><a id="x"></a>', 'dom_clobbering', 'REMOVED');

// テスト実行
$runner->testFullPipeline();
$runner->printReport();
$runner->saveResultJson(__DIR__ . '/result_dom_clobbering.json');
exit($runner->hasFailures() ? 1 : 0);
