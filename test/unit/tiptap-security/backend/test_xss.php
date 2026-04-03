<?php
/**
 * Suite 1: XSS (Stored XSS) テスト — 40件
 *
 * 使い方: php test/unit/tiptap-security/backend/test_xss.php
 */
require_once __DIR__ . '/SecurityTestRunner.php';

$runner = new SecurityTestRunner();

// === 4.1 scriptタグ系 (1-01〜1-07) ===
$runner->addCase('1-01', '<script>alert(1)</script>', 'xss', 'REMOVED');
$runner->addCase('1-02', '<ScRiPt>alert(1)</sCrIpT>', 'xss', 'REMOVED');
$runner->addCase('1-03', "<scr\x00ipt>alert(1)</script>", 'xss', 'REMOVED');
$runner->addCase('1-04', "<scr\nipt>alert(1)</script>", 'xss', 'REMOVED');
$runner->addCase('1-05', "<scr\tipt>alert(1)</script>", 'xss', 'REMOVED');
$runner->addCase('1-06', '<script>alert(1)', 'xss', 'REMOVED');
$runner->addCase('1-07', '<script><script>alert(1)</script></script>', 'xss', 'REMOVED');

// === 4.2 イベント属性系 (1-08〜1-15) ===
$runner->addCase('1-08', '<img src=x onerror="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-09', '<body onload="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-10', '<div onmouseover="alert(1)">test</div>', 'xss', 'REMOVED');
$runner->addCase('1-11', '<input onfocus="alert(1)" autofocus>', 'xss', 'REMOVED');
$runner->addCase('1-12', '<div onanimationend="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-13', '<img src=x ONERROR="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-14', '<img src=x on error="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-15', "<img src=x\tonerror=\"alert(1)\">", 'xss', 'REMOVED');

// === 4.3 javascript: URI系 (1-16〜1-22) ===
$runner->addCase('1-16', '<a href="javascript:alert(1)">click</a>', 'xss', 'REMOVED');
$runner->addCase('1-17', '<a href="JaVaScRiPt:alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-18', "<a href=\"java\tscript:alert(1)\">", 'xss', 'REMOVED');
$runner->addCase('1-19', "<a href=\"java\nscript:alert(1)\">", 'xss', 'REMOVED');
$runner->addCase('1-20', '<a href="&#106;avascript:alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-21', '<a href="vbscript:MsgBox(1)">', 'xss', 'REMOVED');
$runner->addCase('1-22', '<a href="data:text/html,<script>alert(1)</script>">', 'xss', 'REMOVED');

// === 4.4 SVG/MathML系 (1-23〜1-27) ===
$runner->addCase('1-23', '<svg onload="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-24', '<svg><script>alert(1)</script></svg>', 'xss', 'REMOVED');
$runner->addCase('1-25', '<svg><animate onbegin="alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-26', '<math><maction actiontype="statusline">XSS</maction></math>', 'xss', 'REMOVED');
$runner->addCase('1-27', '<svg><foreignObject><body onload="alert(1)">', 'xss', 'REMOVED');

// === 4.5 img/iframe/object系 (1-28〜1-33) ===
$runner->addCase('1-28', '<iframe src="javascript:alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-29', '<iframe srcdoc="<script>alert(1)</script>">', 'xss', 'REMOVED');
$runner->addCase('1-30', '<object data="javascript:alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-31', '<embed src="javascript:alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-32', '<img src=x longdesc="javascript:alert(1)">', 'xss', 'REMOVED');
$runner->addCase('1-33', '<video><source onerror="alert(1)">', 'xss', 'REMOVED');

// === 4.6 style属性によるXSS (1-34〜1-37) ===
$runner->addCase('1-34', '<div style="width:expression(alert(1))">', 'xss', 'REMOVED');
$runner->addCase('1-35', '<div style="-moz-binding:url(evil)">', 'xss', 'REMOVED');
$runner->addCase('1-36', '<div style="behavior:url(evil.htc)">', 'xss', 'REMOVED');
$runner->addCase('1-37', '<div style="background:url(javascript:alert(1))">', 'xss', 'REMOVED');

// === 4.7 テンプレートインジェクション (1-38〜1-40) ===
$runner->addCase('1-38', '<template><script>alert(1)</script></template>', 'xss', 'REMOVED');
$runner->addCase('1-39', '<noscript><img src=x onerror="alert(1)"></noscript>', 'xss', 'REMOVED');
$runner->addCase('1-40', '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', 'xss', 'REMOVED');

// テスト実行
$runner->testFullPipeline();
$runner->printReport();
$runner->saveResultJson(__DIR__ . '/result_xss.json');
exit($runner->hasFailures() ? 1 : 0);
