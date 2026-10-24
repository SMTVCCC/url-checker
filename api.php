<?php
/**
 * URL 安全检测 API - 接收前端请求，返回 JSON 结果
 */
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('X-Content-Type-Options: nosniff');

// 限流 - 简单文件锁防并发攻击
session_start();
$_SESSION['last_check_time'] = $_SESSION['last_check_time'] ?? 0;
$_SESSION['check_count'] = $_SESSION['check_count'] ?? 0;
$now = time();
if ($now - $_SESSION['last_check_time'] < 3) {
    echo json_encode(['ok' => false, 'error' => '请求过于频繁，请稍后再试']);
    exit;
}
if ($now - ($_SESSION['check_count_window'] ?? 0) > 60) {
    $_SESSION['check_count'] = 0;
    $_SESSION['check_count_window'] = $now;
}
if ($_SESSION['check_count'] > 10) {
    echo json_encode(['ok' => false, 'error' => '短时间内请求过多，请稍后再试']);
    exit;
}

$_SESSION['last_check_time'] = $now;
$_SESSION['check_count']++;

// 加载所有模块
require_once __DIR__ . '/includes/UrlParser.php';
require_once __DIR__ . '/includes/DnsChecker.php';
require_once __DIR__ . '/includes/ConnectivityChecker.php';
require_once __DIR__ . '/includes/SslChecker.php';
require_once __DIR__ . '/includes/IpProfiler.php';
require_once __DIR__ . '/includes/ContentAnalyzer.php';
require_once __DIR__ . '/includes/ScoreEngine.php';

// 获取输入
$input = json_decode(file_get_contents('php://input'), true);
if (!$input && isset($_GET['url'])) $input = ['url' => $_GET['url']];

if (empty($input['url'])) {
    echo json_encode(['ok' => false, 'error' => '请输入要检测的 URL']);
    exit;
}

$rawUrl = trim($input['url']);
if (strlen($rawUrl) > 500) {
    echo json_encode(['ok' => false, 'error' => 'URL 过长']);
    exit;
}

$startTime = microtime(true);

try {
    // [1] URL 解析与 SSRF 防护
    $parser = new UrlParser();
    $urlInfo = $parser->parse($rawUrl);
    if ($urlInfo === null) {
        echo json_encode([
            'ok' => false,
            'error' => implode('; ', $parser->getErrors()),
            'warnings' => $parser->getWarnings(),
        ]);
        exit;
    }

    // [2] DNS 解析 + SSRF 二次检查
    $dnsResult = $parser->resolveWithSsrfCheck($urlInfo['host']);
    if ($dnsResult['ssrf_blocked']) {
        echo json_encode([
            'ok' => false,
            'error' => 'DNS 解析到内网 IP，请求已被拦截（SSRF 防护）',
            'blocked_ips' => $dnsResult['blocked_ips'],
        ]);
        exit;
    }

    if (empty($dnsResult['ips'])) {
        echo json_encode([
            'ok' => false,
            'error' => 'DNS 解析失败：' . ($dnsResult['dns_error'] ?? '无可用 IP'),
        ]);
        exit;
    }

    // [3] DNS 深度检测
    $dnsChecker = new DnsChecker();
    $dnsInfo = $dnsChecker->check($urlInfo['host'], $dnsResult['ips']);

    // [4] 连通性 + HTTP
    $connChecker = new ConnectivityChecker();
    $connInfo = $connChecker->check(
        $urlInfo['host'],
        $urlInfo['scheme'],
        $urlInfo['port'],
        $urlInfo['path']
    );

    // [5] SSL 证书
    $sslChecker = new SslChecker();
    $sslInfo = $sslChecker->check($urlInfo['host'], $urlInfo['port']);

    // [6] IP 画像
    $ipProfiler = new IpProfiler();
    $ipInfo = $ipProfiler->check($dnsResult['ips']);

    // [7] 页面内容分析
    $contentChecker = new ContentAnalyzer();
    $body = $connInfo['http_https']['body_preview'] ?? null;
    $contentType = $connInfo['http_https']['headers']['content-type'] ?? '';
    $contentInfo = $contentChecker->analyze($body, $contentType);

    // [8] 综合评分
    $scoreEngine = new ScoreEngine();
    $scoreInfo = $scoreEngine->analyze([
        'url_info'     => array_merge($urlInfo, [
            'errors'   => $parser->getErrors(),
            'warnings' => $parser->getWarnings(),
        ]),
        'dns'          => $dnsInfo,
        'connectivity' => $connInfo,
        'ssl'          => $sslInfo,
        'ip_profile'   => $ipInfo,
        'content'      => $contentInfo,
    ]);

    // 计算耗时
    $elapsed = round(microtime(true) - $startTime, 2);

    // 返回完整结果
    echo json_encode([
        'ok'      => true,
        'elapsed' => $elapsed,
        'url'     => $urlInfo['full_url'],
        'host'    => $urlInfo['host'],
        'ips'     => $dnsResult['ips'],
        'modules' => [
            'url_info'     => $urlInfo,
            'dns'          => $dnsInfo,
            'connectivity' => $connInfo,
            'ssl'          => $sslInfo,
            'ip_profile'   => $ipInfo,
            'content'      => $contentInfo,
        ],
        'score' => $scoreInfo,
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

} catch (Throwable $e) {
    echo json_encode([
        'ok' => false,
        'error' => '检测过程中出现异常: ' . $e->getMessage(),
    ]);
}
