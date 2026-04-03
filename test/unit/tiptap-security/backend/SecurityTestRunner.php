<?php
/**
 * Tiptap脆弱性テスト用PHPテストランナー基盤
 *
 * Save.phpと同じ浄化パイプラインを再現し、XSS・エンコーディングバイパス等の
 * セキュリティテストを実行するためのスタンドアロンテストランナー。
 *
 * 使い方:
 *   php SecurityTestRunner.php                  # 単体実行（デモテスト）
 *   php SecurityTestRunner.php --output=result  # JSON結果を result.json に保存
 *
 * テストスイートからの利用:
 *   require_once __DIR__ . '/SecurityTestRunner.php';
 *   $runner = new SecurityTestRunner();
 *   $runner->addCase('XSS-001', '<script>alert(1)</script>', 'xss', 'REMOVED');
 *   $runner->testFullPipeline();
 *   $runner->printReport();
 */

// メモリ制限の引き上げ（HTMLPurifierは大量メモリを消費する場合がある）
ini_set('memory_limit', '256M');

// F-RevoCRMブートストラップ
chdir('/var/www/html/GitHub');
require_once 'config.php';
require_once 'vendor/autoload.php';
require_once 'includes/runtime/Globals.php';
include_once 'include/utils/utils.php';
include_once 'include/utils/VtlibUtils.php';

/**
 * テスト結果の判定ステータス
 */
class TestVerdict
{
    const OK   = 'OK';    // 期待通り浄化された
    const OK_PARTIAL = 'OK*';  // 部分的に浄化された（改善の余地あり）
    const NG   = 'NG';    // 浄化が不十分（脆弱性の可能性）
    const SKIP = 'SKIP';  // テストスキップ
}

/**
 * 個別テストケースの結果を格納するクラス
 */
class TestResult
{
    /** @var string テストケースID（例: XSS-001） */
    public $id;

    /** @var string テストカテゴリ（例: xss, encoding, preservation） */
    public $category;

    /** @var string テスト対象メソッド名 */
    public $method;

    /** @var string 入力HTML */
    public $input;

    /** @var string 浄化後の出力 */
    public $output;

    /** @var string 期待する判定タイプ（REMOVED / ESCAPED / PRESERVED） */
    public $expectationType;

    /** @var string|null 保持チェック時の検索パターン */
    public $preservePattern;

    /** @var string TestVerdict定数 */
    public $verdict;

    /** @var string 判定理由の説明 */
    public $reason;

    /** @var float 実行時間（ミリ秒） */
    public $durationMs;
}

/**
 * セキュリティテストランナー
 *
 * 浄化パイプラインの各段階をテストし、結果をレポートする。
 */
class SecurityTestRunner
{
    /** @var array テストケース定義 [{id, input, category, expectationType, preservePattern}] */
    private $cases = [];

    /** @var TestResult[] テスト結果 */
    private $results = [];

    /** @var bool ブートストラップ完了フラグ */
    private $bootstrapped = false;

    public function __construct()
    {
        $this->ensureBootstrap();
    }

    /**
     * F-RevoCRM環境のブートストラップを確認する
     *
     * HTMLPurifierインスタンスがグローバル変数に存在することを検証し、
     * 存在しない場合はvtlib_purifyの初回呼び出しで初期化させる。
     *
     * @throws RuntimeException ブートストラップに失敗した場合
     */
    private function ensureBootstrap(): void
    {
        if ($this->bootstrapped) {
            return;
        }

        global $__htmlpurifier_instance;

        // HTMLPurifierがまだ初期化されていない場合、ダミー呼び出しで初期化
        if (empty($__htmlpurifier_instance)) {
            vtlib_purify('<p>bootstrap</p>');
        }

        if (empty($__htmlpurifier_instance)) {
            throw new RuntimeException(
                'HTMLPurifierの初期化に失敗しました。config.phpとvendor/autoload.phpを確認してください。'
            );
        }

        $this->bootstrapped = true;
    }

    /**
     * テストケースを追加する
     *
     * @param string $id              テストケースID（例: XSS-001）
     * @param string $input           テスト入力HTML
     * @param string $category        カテゴリ（xss, encoding, preservation など）
     * @param string $expectationType 期待タイプ: REMOVED=完全除去, ESCAPED=エスケープ, PRESERVED=保持
     * @param string|null $preservePattern PRESERVED時に出力に含まれるべきパターン（正規表現）
     */
    public function addCase(
        string $id,
        string $input,
        string $category,
        string $expectationType,
        ?string $preservePattern = null
    ): void {
        $this->cases[] = [
            'id'              => $id,
            'input'           => $input,
            'category'        => $category,
            'expectationType' => strtoupper($expectationType),
            'preservePattern' => $preservePattern,
        ];
    }

    /**
     * 登録済みテストケース数を返す
     *
     * @return int
     */
    public function getCaseCount(): int
    {
        return count($this->cases);
    }

    /**
     * テスト結果配列を返す
     *
     * @return TestResult[]
     */
    public function getResults(): array
    {
        return $this->results;
    }

    // =========================================================================
    //  浄化メソッド（テスト対象パイプライン）
    // =========================================================================

    /**
     * vtlib_purify のみで浄化する
     *
     * @param string $input 入力HTML
     * @return string 浄化後HTML
     */
    private function applyVtlibPurify(string $input): string
    {
        // vtlib_purifyは内部キャッシュを使用するため、
        // 同一入力でキャッシュヒットしないよう注意
        // （テストでは毎回異なる入力が想定されるため問題なし）
        return vtlib_purify($input);
    }

    /**
     * purifyHtmlEventAttributes のみで浄化する
     *
     * @param string $input 入力HTML
     * @return string 浄化後HTML
     */
    private function applyPurifyEventAttrs(string $input): string
    {
        return purifyHtmlEventAttributes($input, true);
    }

    /**
     * Save.phpと同じ処理順序で浄化する
     *
     * Save.php L173-175 の処理を再現:
     *   1. decode_html($fieldValue)
     *   2. vtlib_purify(上記の結果)
     *   3. decode_html(上記の結果)
     *   4. purifyHtmlEventAttributes(上記の結果, true)
     *
     * @param string $input 入力HTML
     * @return string 浄化後HTML
     */
    private function applyFullPipeline(string $input): string
    {
        // Step 1: HTMLエンティティをデコード
        $step1 = decode_html($input);

        // Step 2: HTMLPurifier + イベント属性除去
        $step2 = vtlib_purify($step1);

        // Step 3: 再度HTMLエンティティをデコード
        $step3 = decode_html($step2);

        // Step 4: イベント属性除去（replaceAll=true）
        $step4 = purifyHtmlEventAttributes($step3, true);

        return $step4;
    }

    // =========================================================================
    //  テスト実行メソッド
    // =========================================================================

    /**
     * vtlib_purifyのみでテストを実行する
     *
     * 全登録ケースに対してvtlib_purifyを適用し、結果を判定する。
     */
    public function testVtlibPurify(): void
    {
        $this->runTestsWith('vtlib_purify', function (string $input): string {
            return $this->applyVtlibPurify($input);
        });
    }

    /**
     * purifyHtmlEventAttributesのみでテストを実行する
     *
     * 全登録ケースに対してpurifyHtmlEventAttributesを適用し、結果を判定する。
     */
    public function testPurifyEventAttrs(): void
    {
        $this->runTestsWith('purifyEventAttrs', function (string $input): string {
            return $this->applyPurifyEventAttrs($input);
        });
    }

    /**
     * Save.phpと同じフルパイプラインでテストを実行する
     *
     * 全登録ケースに対してフルパイプラインを適用し、結果を判定する。
     */
    public function testFullPipeline(): void
    {
        $this->runTestsWith('fullPipeline', function (string $input): string {
            return $this->applyFullPipeline($input);
        });
    }

    /**
     * 浄化後に特定HTMLが保持されることを検証する
     *
     * category=preservation のケースのみ対象。
     * フルパイプライン後に preservePattern が出力に含まれることを検証する。
     */
    public function testPreserved(): void
    {
        foreach ($this->cases as $case) {
            if ($case['category'] !== 'preservation') {
                continue;
            }

            $startTime = microtime(true);
            $output = $this->applyFullPipeline($case['input']);
            $durationMs = (microtime(true) - $startTime) * 1000;

            $result = new TestResult();
            $result->id              = $case['id'];
            $result->category        = $case['category'];
            $result->method          = 'preserved';
            $result->input           = $case['input'];
            $result->output          = $output;
            $result->expectationType = 'PRESERVED';
            $result->preservePattern = $case['preservePattern'];
            $result->durationMs      = round($durationMs, 3);

            $this->judgePreservation($result, $case['preservePattern']);
            $this->results[] = $result;
        }
    }

    /**
     * 指定した浄化関数で全ケースをテスト実行する共通メソッド
     *
     * @param string   $methodName テスト対象メソッド名（レポート表示用）
     * @param callable $purifyFn  浄化関数 function(string $input): string
     */
    private function runTestsWith(string $methodName, callable $purifyFn): void
    {
        foreach ($this->cases as $case) {
            $startTime = microtime(true);

            // メモリ不足対策: 極端に大きな入力は事前チェック
            if (strlen($case['input']) > 1048576) { // 1MB超
                $result = new TestResult();
                $result->id              = $case['id'];
                $result->category        = $case['category'];
                $result->method          = $methodName;
                $result->input           = mb_substr($case['input'], 0, 200) . '...(truncated)';
                $result->output          = '';
                $result->expectationType = $case['expectationType'];
                $result->preservePattern = $case['preservePattern'];
                $result->verdict         = TestVerdict::SKIP;
                $result->reason          = '入力サイズが1MBを超過（メモリ保護）';
                $result->durationMs      = 0;
                $this->results[] = $result;
                continue;
            }

            $output = $purifyFn($case['input']);
            $durationMs = (microtime(true) - $startTime) * 1000;

            $result = new TestResult();
            $result->id              = $case['id'];
            $result->category        = $case['category'];
            $result->method          = $methodName;
            $result->input           = $case['input'];
            $result->output          = $output;
            $result->expectationType = $case['expectationType'];
            $result->preservePattern = $case['preservePattern'];
            $result->durationMs      = round($durationMs, 3);

            $this->judge($result);
            $this->results[] = $result;
        }
    }

    // =========================================================================
    //  判定ロジック
    // =========================================================================

    /**
     * テスト結果を判定する
     *
     * expectationTypeに応じて適切な判定ロジックを適用する。
     *
     * @param TestResult $result 判定対象の結果オブジェクト
     */
    private function judge(TestResult $result): void
    {
        switch ($result->expectationType) {
            case 'REMOVED':
                $this->judgeRemoved($result);
                break;
            case 'ESCAPED':
                $this->judgeEscaped($result);
                break;
            case 'PRESERVED':
                $this->judgePreservation($result, $result->preservePattern);
                break;
            default:
                $result->verdict = TestVerdict::SKIP;
                $result->reason  = "不明なexpectationType: {$result->expectationType}";
        }
    }

    /**
     * REMOVED判定: 危険なコンテンツが完全に除去されたことを検証
     *
     * 以下のパターンが出力に含まれていないことを確認:
     *   - <script タグ
     *   - javascript: プロトコル
     *   - on* イベントハンドラ属性（= 付き）
     *   - <iframe, <object, <embed タグ
     *   - expression() CSS
     *   - vbscript: プロトコル
     *   - data: プロトコル（text/html）
     *
     * @param TestResult $result 判定対象
     */
    private function judgeRemoved(TestResult $result): void
    {
        $output = $result->output;
        $dangers = [];

        // 危険パターンの検出
        $dangerPatterns = [
            'script_tag'       => '/<script[\s>]/i',
            'javascript_proto' => '/javascript\s*:/i',
            'event_handler'    => '/\bon\w+\s*=/i',
            'iframe_tag'       => '/<iframe[\s>]/i',
            'object_tag'       => '/<object[\s>]/i',
            'embed_tag'        => '/<embed[\s>]/i',
            'expression_css'   => '/expression\s*\(/i',
            'vbscript_proto'   => '/vbscript\s*:/i',
            'data_html_proto'  => '/data\s*:\s*text\/html/i',
        ];

        foreach ($dangerPatterns as $name => $pattern) {
            if (preg_match($pattern, $output)) {
                $dangers[] = $name;
            }
        }

        if (empty($dangers)) {
            $result->verdict = TestVerdict::OK;
            $result->reason  = '危険なコンテンツは検出されませんでした';
        } else {
            // 入力にも同じパターンがあったか確認（元々安全な入力の誤検出を防ぐ）
            $inputDangers = [];
            foreach ($dangerPatterns as $name => $pattern) {
                if (preg_match($pattern, $result->input)) {
                    $inputDangers[] = $name;
                }
            }

            // 出力で検出されたが入力にはなかったパターンは浄化で生成された（異常）
            $newDangers = array_diff($dangers, $inputDangers);
            if (!empty($newDangers)) {
                $result->verdict = TestVerdict::NG;
                $result->reason  = '浄化処理で新たな危険パターンが生成: ' . implode(', ', $newDangers);
            } else {
                // 入力にあった危険パターンが残存
                $result->verdict = TestVerdict::NG;
                $result->reason  = '危険パターンが残存: ' . implode(', ', $dangers);
            }
        }
    }

    /**
     * ESCAPED判定: 危険なコンテンツがエスケープされたことを検証
     *
     * 出力にHTMLエンティティ化された形跡があればOK。
     * 生のスクリプトタグやイベントハンドラが残っていればNG。
     *
     * @param TestResult $result 判定対象
     */
    private function judgeEscaped(TestResult $result): void
    {
        $output = $result->output;

        // エスケープの形跡を確認
        $escapedIndicators = [
            '&lt;',
            '&gt;',
            '&amp;',
            '&quot;',
            '&#',
            '&equals;',
        ];

        $hasEscaped = false;
        foreach ($escapedIndicators as $indicator) {
            if (stripos($output, $indicator) !== false) {
                $hasEscaped = true;
                break;
            }
        }

        // 生の危険パターンが残っているか確認
        $hasDanger = (bool) preg_match('/<script[\s>]|javascript\s*:|on\w+\s*=/i', $output);

        if ($hasEscaped && !$hasDanger) {
            $result->verdict = TestVerdict::OK;
            $result->reason  = '正しくエスケープされました';
        } elseif (!$hasDanger) {
            // エスケープではなく除去された場合もOK（より安全）
            $result->verdict = TestVerdict::OK_PARTIAL;
            $result->reason  = 'エスケープではなく除去されました（安全ですが期待と異なります）';
        } else {
            $result->verdict = TestVerdict::NG;
            $result->reason  = '危険パターンが未エスケープで残存';
        }
    }

    /**
     * PRESERVED判定: 浄化後に特定パターンが保持されていることを検証
     *
     * @param TestResult $result         判定対象
     * @param string|null $preservePattern 出力に含まれるべき正規表現パターン
     */
    private function judgePreservation(TestResult $result, ?string $preservePattern): void
    {
        if ($preservePattern === null) {
            $result->verdict = TestVerdict::SKIP;
            $result->reason  = 'preservePatternが未指定';
            return;
        }

        $output = $result->output;

        // preservePatternが正規表現として有効か確認
        if (@preg_match($preservePattern, '') === false) {
            $result->verdict = TestVerdict::SKIP;
            $result->reason  = "無効な正規表現パターン: {$preservePattern}";
            return;
        }

        if (preg_match($preservePattern, $output)) {
            $result->verdict = TestVerdict::OK;
            $result->reason  = '期待するHTMLが保持されています';
        } else {
            $result->verdict = TestVerdict::NG;
            $result->reason  = '期待するHTMLが浄化で除去されました';
        }
    }

    // =========================================================================
    //  レポート出力
    // =========================================================================

    /**
     * テスト結果をコンソールに出力する
     *
     * 各テストケースのID、メソッド、判定（OK / OK* / NG / SKIP）、理由を表示し、
     * 末尾にサマリーを出力する。
     */
    public function printReport(): void
    {
        echo str_repeat('=', 78) . "\n";
        echo "  Tiptap Security Test Report\n";
        echo str_repeat('=', 78) . "\n\n";

        $counts = ['OK' => 0, 'OK*' => 0, 'NG' => 0, 'SKIP' => 0];

        foreach ($this->results as $r) {
            $verdictDisplay = str_pad($r->verdict, 4);
            $idDisplay      = str_pad($r->id, 12);
            $methodDisplay  = str_pad($r->method, 18);
            $timeDisplay    = sprintf('%7.2fms', $r->durationMs);

            echo "  [{$verdictDisplay}] {$idDisplay} {$methodDisplay} {$timeDisplay}  {$r->reason}\n";

            if (isset($counts[$r->verdict])) {
                $counts[$r->verdict]++;
            }
        }

        $total = count($this->results);
        echo "\n" . str_repeat('-', 78) . "\n";
        echo "  Total: {$total}  |  ";
        echo "OK: {$counts['OK']}  |  ";
        echo "OK*: {$counts['OK*']}  |  ";
        echo "NG: {$counts['NG']}  |  ";
        echo "SKIP: {$counts['SKIP']}\n";
        echo str_repeat('=', 78) . "\n";
    }

    /**
     * テスト結果をJSONファイルに保存する
     *
     * @param string $filePath 出力先ファイルパス
     * @throws RuntimeException ファイル書き込みに失敗した場合
     */
    public function saveResultJson(string $filePath): void
    {
        $data = [
            'generated_at' => date('Y-m-d\TH:i:sP'),
            'php_version'  => PHP_VERSION,
            'summary'      => $this->buildSummary(),
            'results'      => [],
        ];

        foreach ($this->results as $r) {
            $data['results'][] = [
                'id'              => $r->id,
                'category'        => $r->category,
                'method'          => $r->method,
                'input'           => mb_convert_encoding($r->input, 'UTF-8', 'UTF-8'),
                'output'          => mb_convert_encoding($r->output, 'UTF-8', 'UTF-8'),
                'expectationType' => $r->expectationType,
                'verdict'         => $r->verdict,
                'reason'          => $r->reason,
                'durationMs'      => $r->durationMs,
            ];
        }

        $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) {
            throw new RuntimeException('JSON変換に失敗しました: ' . json_last_error_msg());
        }

        $written = file_put_contents($filePath, $json);
        if ($written === false) {
            throw new RuntimeException("ファイル書き込みに失敗しました: {$filePath}");
        }

        echo "\n結果をJSONに保存しました: {$filePath}\n";
    }

    /**
     * テスト結果のサマリーを構築する
     *
     * @return array サマリー情報の連想配列
     */
    private function buildSummary(): array
    {
        $counts = ['OK' => 0, 'OK*' => 0, 'NG' => 0, 'SKIP' => 0];

        foreach ($this->results as $r) {
            if (isset($counts[$r->verdict])) {
                $counts[$r->verdict]++;
            }
        }

        return [
            'total' => count($this->results),
            'ok'    => $counts['OK'],
            'ok_partial' => $counts['OK*'],
            'ng'    => $counts['NG'],
            'skip'  => $counts['SKIP'],
        ];
    }

    /**
     * FAIL（NG）件数があるかどうかを判定する
     *
     * @return bool NG件数が1件以上の場合true
     */
    public function hasFailures(): bool
    {
        foreach ($this->results as $r) {
            if ($r->verdict === TestVerdict::NG) {
                return true;
            }
        }
        return false;
    }

    /**
     * テスト結果をリセットする（テストメソッド切り替え時に使用）
     */
    public function resetResults(): void
    {
        $this->results = [];
    }
}

// =============================================================================
//  CLI直接実行時のデモ
// =============================================================================

if (php_sapi_name() === 'cli' && realpath($argv[0]) === realpath(__FILE__)) {
    echo "SecurityTestRunner デモ実行\n\n";

    $runner = new SecurityTestRunner();

    // デモ用テストケース
    // XSS: 除去されるべき入力
    $runner->addCase(
        'DEMO-XSS-001',
        '<p>テスト<script>alert("xss")</script></p>',
        'xss',
        'REMOVED'
    );
    $runner->addCase(
        'DEMO-XSS-002',
        '<img src=x onerror="alert(1)">',
        'xss',
        'REMOVED'
    );
    $runner->addCase(
        'DEMO-XSS-003',
        '<a href="javascript:alert(1)">click</a>',
        'xss',
        'REMOVED'
    );

    // 保持: 浄化後も残るべき安全なHTML
    $runner->addCase(
        'DEMO-PRSV-001',
        '<p style="color: red;">テスト段落</p>',
        'preservation',
        'PRESERVED',
        '/<p[^>]*>テスト段落<\/p>/'
    );
    $runner->addCase(
        'DEMO-PRSV-002',
        '<table><tr><td>セル</td></tr></table>',
        'preservation',
        'PRESERVED',
        '/<table>/'
    );

    // フルパイプラインテスト
    echo "--- Full Pipeline ---\n";
    $runner->testFullPipeline();

    // 保持テスト
    echo "--- Preservation ---\n";
    $runner->testPreserved();

    $runner->printReport();

    // --output オプション処理
    $outputFile = null;
    foreach ($argv as $arg) {
        if (strpos($arg, '--output=') === 0) {
            $outputFile = substr($arg, strlen('--output='));
        }
    }

    if ($outputFile !== null) {
        if (pathinfo($outputFile, PATHINFO_EXTENSION) !== 'json') {
            $outputFile .= '.json';
        }
        $runner->saveResultJson($outputFile);
    }

    exit($runner->hasFailures() ? 1 : 0);
}
