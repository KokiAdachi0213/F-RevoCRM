<?php
/**
 * Suite 2: エンコーディングバイパス テスト — 17件
 *
 * 使い方: php test/unit/tiptap-security/backend/test_encoding_bypass.php
 */
require_once __DIR__ . '/SecurityTestRunner.php';

$runner = new SecurityTestRunner();

// === 5.1 HTMLエンティティバイパス (2-01〜2-05) ===
$runner->addCase('2-01', '&#60;script&#62;alert(1)&#60;/script&#62;', 'encoding', 'REMOVED');
$runner->addCase('2-02', '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;', 'encoding', 'REMOVED');
$runner->addCase('2-03', '&#60script&#62alert(1)&#60/script&#62', 'encoding', 'REMOVED');
$runner->addCase('2-04', '&#0000060;script&#0000062;', 'encoding', 'REMOVED');
$runner->addCase('2-05', '&lt;script&gt;alert(&#49;)&lt;/script&gt;', 'encoding', 'REMOVED');

// === 5.2 二重デコード (2-06〜2-09) ===
$runner->addCase('2-06', '&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;', 'encoding', 'REMOVED');
$runner->addCase('2-07', '%3Cscript%3Ealert(1)%3C/script%3E', 'encoding', 'REMOVED');
$runner->addCase('2-08', '%253Cscript%253Ealert(1)%253C/script%253E', 'encoding', 'REMOVED');
$runner->addCase('2-09', '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;', 'encoding', 'REMOVED');

// === 5.3 UTF-8バイパス (2-10〜2-12) ===
$runner->addCase('2-10', "\xC0\xBCscript\xC0\xBEalert(1)\xC0\xBC/script\xC0\xBE", 'encoding', 'REMOVED');
$runner->addCase('2-11', "\xEF\xBB\xBF<script>alert(1)</script>", 'encoding', 'REMOVED');
$runner->addCase('2-12', '+ADw-script+AD4-alert(1)+ADw-/script+AD4-', 'encoding', 'REMOVED');

// === 5.4 null/制御文字バイパス (2-13〜2-17) ===
$runner->addCase('2-13', "<scri\x00pt>alert(1)</script>", 'encoding', 'REMOVED');
$runner->addCase('2-14', "<img src=x on\x00error=\"alert(1)\">", 'encoding', 'REMOVED');
$runner->addCase('2-15', "<img src=x o\x08nerror=\"alert(1)\">", 'encoding', 'REMOVED');
$runner->addCase('2-16', "<scr\xE2\x80\x8Bipt>alert(1)</script>", 'encoding', 'REMOVED');
$runner->addCase('2-17', "<img src=x on\xE2\x80\x8Berror=\"alert(1)\">", 'encoding', 'REMOVED');

// テスト実行
$runner->testFullPipeline();
$runner->printReport();
$runner->saveResultJson(__DIR__ . '/result_encoding_bypass.json');
exit($runner->hasFailures() ? 1 : 0);
