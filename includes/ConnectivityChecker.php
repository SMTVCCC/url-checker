<?php
/**
 * 连通性 / HTTP 响应 / 端口检测模块
 */
class ConnectivityChecker
{
    private const CONNECT_TIMEOUT = 5;
    private const TIMEOUT = 10;

    public function check(string $host, string $scheme = 'https', int $port = 443, string $path = '/'): array
    {
        $result = [
            'tcp_ports' => [],
            'http_https' => null,
            'http_plain' => null,
            'http_head_response' => null,
            'screenshot_available' => false,
            'issues' => [],
        ];

        // 端口检测 (常用端口)
        $commonPorts = [21, 22, 80, 443, 8080, 8443, 3000, 5000];
        foreach ($commonPorts as $p) {
            $result['tcp_ports'][$p] = $this->testPort($host, $p);
        }

        // HTTPS 请求
        $result['http_https'] = $this->httpRequest($scheme . '://' . $host . ':' . $port . $path);

        // HTTP 请求 (跟随跳转)
        $result['http_plain'] = $this->httpRequest('http://' . $host . $path);

        // HEAD 请求 (快速检测响应头)
        $result['http_head_response'] = $this->httpHead($scheme . '://' . $host . ':' . $port . $path);

        // 响应头安全检测
        if (!empty($result['http_https']['headers'])) {
            $result['security_headers'] = $this->analyzeSecurityHeaders($result['http_https']['headers']);
        }

        // 生成风险
        $this->generateIssues($result);

        return $result;
    }

    private function testPort(string $host, int $port): array
    {
        $start = microtime(true);

        // 优先尝试直连
        $fp = @stream_socket_client(
            $host . ':' . $port,
            $errno, $errstr,
            self::CONNECT_TIMEOUT,
            STREAM_CLIENT_CONNECT
        );

        // 直连失败且有代理，则通过 HTTP CONNECT 代理检测
        if (!$fp && !empty($_ENV['https_proxy'])) {
            $proxy = parse_url($_ENV['https_proxy']);
            $proxyFp = @stream_socket_client(
                ($proxy['host'] ?? '127.0.0.1') . ':' . ($proxy['port'] ?? 8080),
                $errno, $errstr,
                self::CONNECT_TIMEOUT,
                STREAM_CLIENT_CONNECT
            );
            if ($proxyFp) {
                fwrite($proxyFp, "CONNECT {$host}:{$port} HTTP/1.1\r\nHost: {$host}:{$port}\r\n\r\n");
                $resp = fgets($proxyFp);
                if (str_contains($resp ?? '', '200')) {
                    fclose($proxyFp);
                    $fp = true; // 标记已检测到
                } else {
                    fclose($proxyFp);
                }
            }
        }

        $latency = round((microtime(true) - $start) * 1000, 1);

        if ($fp) {
            if (is_resource($fp)) fclose($fp);
            return ['open' => true, 'latency_ms' => $latency, 'error' => null];
        }
        return ['open' => false, 'latency_ms' => null, 'error' => $errstr];
    }

    private function httpRequest(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 URLChecker/1.0',
            CURLOPT_HTTPHEADER     => [
                'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8',
                'Cache-Control: no-cache',
            ],
        ]);

        $response = curl_exec($ch);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            return [
                'success' => false,
                'http_code' => 0,
                'headers' => [],
                'body_preview' => '',
                'body_size' => 0,
                'total_time' => round($totalTime, 3),
                'error' => $error,
                'redirect_url' => null,
            ];
        }

        $headerStr = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        $headers = $this->parseHeaders($headerStr);

        return [
            'success' => true,
            'http_code' => $httpCode,
            'headers' => $headers,
            'body_preview' => substr($body, 0, 3000),
            'body_size' => strlen($body),
            'total_time' => round($totalTime, 3),
            'error' => null,
            'redirect_url' => $redirectUrl,
        ];
    }

    private function httpHead(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_USERAGENT      => 'Mozilla/5.0 URLChecker',
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            return ['success' => false, 'http_code' => 0, 'headers' => [], 'error' => $error];
        }

        return [
            'success' => true,
            'http_code' => $httpCode,
            'headers' => $this->parseHeaders($response),
            'error' => null,
        ];
    }

    private function parseHeaders(string $raw): array
    {
        $headers = [];
        $lines = explode("\r\n", $raw);
        foreach ($lines as $line) {
            if (strpos($line, ':') !== false) {
                [$key, $val] = explode(':', $line, 2);
                $headers[trim(strtolower($key))] = trim($val);
            }
        }
        return $headers;
    }

    private function analyzeSecurityHeaders(array $headers): array
    {
        $checks = [
            'strict-transport-security' => ['name' => 'HSTS',      'desc' => '强制 HTTPS'],
            'x-content-type-options'    => ['name' => 'X-Content-Type-Options', 'desc' => 'MIME 嗅探防护'],
            'x-frame-options'          => ['name' => 'X-Frame-Options', 'desc' => '点击劫持防护'],
            'content-security-policy'   => ['name' => 'CSP',       'desc' => '内容安全策略'],
            'x-xss-protection'         => ['name' => 'X-XSS-Protection', 'desc' => 'XSS 过滤'],
            'referrer-policy'          => ['name' => 'Referrer-Policy', 'desc' => '引用策略'],
            'permissions-policy'       => ['name' => 'Permissions-Policy', 'desc' => '功能权限控制'],
        ];
        $result = [];
        foreach ($checks as $key => $info) {
            $result[$key] = [
                'name'  => $info['name'],
                'desc'  => $info['desc'],
                'present' => isset($headers[$key]),
                'value'   => $headers[$key] ?? null,
            ];
        }
        return $result;
    }

    private function generateIssues(array &$result): void
    {
        // TCP 端口 443 可达但 HTTP 握手失败
        if (!empty($result['tcp_ports'][443]['open'])) {
            if ($result['http_https']['http_code'] === 0 && $result['http_https']['error']) {
                $result['issues'][] = 'TCP 443 端口可达，但 TLS/HTTP 握手失败（可能有主动连接拦截/WAF）';
            }
        }

        // HTTP 返回 403/444/主动断开
        $code = $result['http_https']['http_code'] ?? 0;
        if ($code === 403 || $code === 401) {
            $result['issues'][] = "服务器返回 {$code}，需要认证或被拦截";
        }
        if ($code === 0 && !empty($result['tcp_ports'][443]['open'])) {
            $result['issues'][] = '连接成功建立但服务器未返回 HTTP 数据（主动关闭连接特征）';
        }

        // 安全头缺失
        if (!empty($result['security_headers'])) {
            $missing = [];
            foreach ($result['security_headers'] as $h) {
                if (!$h['present']) $missing[] = $h['name'];
            }
            if (count($missing) > 3) {
                $result['issues'][] = '缺失多个安全响应头: ' . implode(', ', $missing);
            }
        }
    }
}
