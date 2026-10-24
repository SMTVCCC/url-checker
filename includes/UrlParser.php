<?php
/**
 * URL 解析与 SSRF 防护模块
 */
class UrlParser
{
    private array $errors = [];
    private array $warnings = [];

    // 内网/本地 IP 段 - SSRF 黑名单
    private array $privateRanges = [
        ['10.0.0.0', '10.255.255.255'],
        ['172.16.0.0', '172.31.255.255'],
        ['192.168.0.0', '192.168.255.255'],
        ['127.0.0.0', '127.255.255.255'],
        ['0.0.0.0', '0.255.255.255'],
        ['169.254.0.0', '169.254.255.255'],
        ['::1', '::1'],
        ['fc00::', 'feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'],
        ['localhost', 'localhost'],
    ];

    // 短链服务识别
    private array $shortUrlServices = [
        'bit.ly', 't.ly', 'tinyurl.com', 'ow.ly', 'is.gd',
        'buff.ly', 'j.mp', 'lnkd.in', 'goo.gl', 'fb.me',
        't.cn', 'dwz.cn', 'url.cn', 'suo.im', '2.vc',
        'short.gy', 'clck.ru', 'v.gd', 'shrinke.me',
    ];

    /**
     * 解析并校验 URL
     */
    public function parse(string $rawUrl): ?array
    {
        $rawUrl = trim($rawUrl);
        if ($rawUrl === '') {
            $this->errors[] = 'URL 不能为空';
            return null;
        }

        // 补全协议
        if (!preg_match('#^https?://#i', $rawUrl)) {
            $rawUrl = 'https://' . $rawUrl;
        }

        // 过滤掉 PHP 协议伪标记
        if (preg_match('#^(php|file|data|gopher|dict|ftp|ftps)://#i', $rawUrl)) {
            $this->errors[] = '不支持的协议: ' . parse_url($rawUrl, PHP_URL_SCHEME);
            return null;
        }

        $parsed = @parse_url($rawUrl);
        if (!$parsed || empty($parsed['host'])) {
            $this->errors[] = 'URL 格式无效，无法解析主机名';
            return null;
        }

        $host = $parsed['host'];

        // 禁止 IP 直接访问（避免 SSRF 绕过 DNS Rebinding）
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $this->errors[] = '不能直接输入 IP 地址，请使用域名';
            return null;
        }

        // 禁止 localhost / 内网域名
        if ($this->isPrivateHostname($host)) {
            $this->errors[] = '禁止检测内网或本地地址（SSRF 防护）';
            return null;
        }

        $scheme = $parsed['scheme'] ?? 'https';
        $port = $parsed['port'] ?? ($scheme === 'https' ? 443 : 80);
        $path = $parsed['path'] ?? '/';
        $query = $parsed['query'] ?? '';
        $fragment = $parsed['fragment'] ?? '';
        $fullUrl = $scheme . '://' . $host;
        if ($port !== 443 && $port !== 80) $fullUrl .= ':' . $port;
        $fullUrl .= $path . ($query ? '?' . $query : '') . ($fragment ? '#' . $fragment : '');

        // 随机度分析
        $randomness = $this->calculateRandomness($host);
        $pathRandomness = $this->calculateRandomness($path);

        // 可疑关键字
        $suspiciousKeywords = $this->detectSuspiciousKeywords($host . ' ' . $path);

        // 是否短链
        $isShortUrl = $this->isShortUrlService($host);
        if ($isShortUrl) {
            $this->warnings[] = '检测到短链服务：' . $host . '，建议谨慎访问';
        }

        // 子域名数量
        $subdomainCount = substr_count($host, '.') - 1;

        return [
            'raw'          => $rawUrl,
            'scheme'       => $scheme,
            'host'         => $host,
            'port'         => $port,
            'path'         => $path,
            'query'        => $query,
            'full_url'     => $fullUrl,
            'is_ip'        => false,
            'is_short_url' => $isShortUrl,
            'subdomain_count' => $subdomainCount,
            'host_randomness'  => $randomness,
            'path_randomness'  => $pathRandomness,
            'suspicious_keywords' => $suspiciousKeywords,
        ];
    }

    /**
     * DNS 解析并检查 SSRF
     */
    public function resolveWithSsrfCheck(string $host): array
    {
        $ips = [];
        $dnsError = null;

        // 先查 A 记录
        $records = @dns_get_record($host, DNS_A);
        if ($records === false) {
            $dnsError = 'DNS 解析失败: ' . error_get_last()['message'] ?? 'unknown';
        } else {
            foreach ($records as $r) {
                $ips[] = $r['ip'];
            }
        }

        // 如果 dns_get_record 不可用，退回到 gethostbyname
        if (empty($ips)) {
            $ip = @gethostbyname($host);
            if ($ip && $ip !== $host) $ips[] = $ip;
        }

        // SSRF 检查：解析出的 IP 不能是内网
        $ssrfBlocked = false;
        $blockedIps = [];
        foreach ($ips as $ip) {
            if ($this->isPrivateIp($ip)) {
                $ssrfBlocked = true;
                $blockedIps[] = $ip;
            }
        }

        return [
            'ips'          => $ips,
            'dns_error'    => $dnsError,
            'ssrf_blocked' => $ssrfBlocked,
            'blocked_ips'  => $blockedIps,
        ];
    }

    public function getErrors(): array   { return $this->errors; }
    public function getWarnings(): array { return $this->warnings; }

    // ========== 内部方法 ==========

    private function isPrivateHostname(string $host): bool
    {
        $host = strtolower($host);
        if ($host === 'localhost' || str_ends_with($host, '.local') || str_ends_with($host, '.lan')) return true;
        if (preg_match('/\.home$/i', $host)) return true;
        return false;
    }

    private function isPrivateIp(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }
        // 额外检查 127.x / 0.x
        $first = (int)explode('.', $ip)[0];
        if ($first === 127 || $first === 0 || $first === 169) return true;
        return false;
    }

    private function calculateRandomness(string $str): array
    {
        $str = strtolower($str);
        $chars = count_chars($str, 1);
        $len = strlen($str);
        if ($len <= 1) return ['entropy' => 0, 'high' => false];

        // Shannon entropy
        $entropy = 0;
        foreach ($chars as $count) {
            $p = $count / $len;
            $entropy -= $p * log($p, 2);
        }

        // 连续辅音检测 (随机域名特征)
        $consonantRuns = preg_match_all('/[bcdfghjklmnpqrstvwxyz]{3,}/', $str);
        $hasDigits = preg_match('/\d/', $str);
        $hasMixed = preg_match('/[a-z]\d|\d[a-z]/', $str);

        // 启发式判定
        $score = 0;
        if ($entropy > 3.5) $score += 2;
        if ($consonantRuns >= 2) $score += 2;
        if ($hasMixed) $score += 1;
        if ($len > 8 && $hasDigits) $score += 1;

        return [
            'entropy'         => round($entropy, 3),
            'consonant_runs'  => $consonantRuns,
            'has_digits'      => (bool)$hasDigits,
            'has_mixed'       => (bool)$hasMixed,
            'high'            => $score >= 3,
        ];
    }

    private function detectSuspiciousKeywords(string $text): array
    {
        $keywords = [
            'login', 'signin', 'verify', 'confirm', 'update', 'secure',
            'account', 'password', 'verify', 'check', 'auth',
            'apple-id', 'icloud', 'paypal', 'amazon', 'netflix',
            'bank', 'sms', 'verify', 'otp', 'code',
            'gift', 'reward', 'free', 'win', 'prize', 'urgent',
            'download', 'install', 'apk', 'exe', 'dll',
            'microsoft', 'google', 'facebook', 'instagram',
        ];
        $found = [];
        $lower = strtolower($text);
        foreach ($keywords as $kw) {
            if (str_contains($lower, $kw)) $found[] = $kw;
        }
        return array_unique($found);
    }

    private function isShortUrlService(string $host): bool
    {
        return in_array(strtolower($host), $this->shortUrlServices, true);
    }
}
