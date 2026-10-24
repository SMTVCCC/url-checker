<?php
/**
 * 页面内容分析模块 - JS / 表单 / 可疑脚本扫描
 */
class ContentAnalyzer
{
    private array $suspiciousPatterns = [
        'keylogger'   => '/addEventListener\s*\(\s*[\'"]key(down|press|up)[\'"]/',
        'clipboard'   => '/navigator\.clipboard|document\.execCommand\s*\(\s*[\'"]copy/',
        'data_exfil'  => '/fetch\s*\(\s*[\'"][\'"]|XMLHttpRequest\s*\(\s*\)|navigator\.sendBeacon/',
        'eval'        => '/\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\'"`]\${/',
        'obfuscated'  => '/fromCharCode|atob\s*\(|unescape\s*\(|decodeURIComponent\s*\(\s*[\'"]%/',
        'crypto_miner'=> '/cryptonight|coinhive|minero|crypto-loot|wasm\s*\(\s*\)/i',
        'redirect'    => '/window\.location\.(href|replace)|document\.location|meta\s+http-equiv\s*=\s*[\'"]refresh/i',
        'phish_form'  => '/(apple-id|icloud|paypal|netflix|amazon)\s*(login|sign|verify)/i',
        'fake_input'  => '/(password|credit.?card|cvv|ssn|driver.?license)/i',
        'download_exe'=> '/\.exe[\'"]|\.apk[\'"]|\.dmg[\'"]|\.msi[\'"]/',
    ];

    private array $phishingKeywords = [
        'verify your account', 'confirm your identity', 'your account will be suspended',
        'immediate action required', 'your password has been compromised',
        'click here within 24 hours', 'failure to comply', 'urgent: security alert',
        '请验证您的账户', '账户将被冻结', '立即验证', '安全警报', '账户异常登录',
    ];

    public function analyze(?string $body, string $contentType = ''): array
    {
        $result = [
            'has_body'      => false,
            'content_size'  => 0,
            'content_type'  => $contentType,
            'html_title'    => null,
            'forms'         => [],
            'scripts'       => [],
            'script_count'  => 0,
            'external_urls' => [],
            'redirects'     => [],
            'pattern_matches' => [],
            'phishing_keywords' => [],
            'issues'        => [],
        ];

        if (empty($body)) {
            $result['issues'][] = '无法获取页面内容（服务器未返回数据或主动断开）';
            return $result;
        }

        $result['has_body'] = true;
        $result['content_size'] = strlen($body);

        // HTML 标题
        if (preg_match('/<title[^>]*>(.*?)<\/title>/is', $body, $m)) {
            $result['html_title'] = trim(html_entity_decode(strip_tags($m[1])));
        }

        // 表单分析
        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        $dom->loadHTML('<?xml encoding="UTF-8">' . $body, LIBXML_NOERROR | LIBXML_NOWARNING);
        if ($dom) {
            $forms = $dom->getElementsByTagName('form');
            foreach ($forms as $form) {
                $inputs = [];
                foreach ($form->getElementsByTagName('input') as $input) {
                    $inputs[] = [
                        'type'  => $input->getAttribute('type'),
                        'name'  => $input->getAttribute('name'),
                        'placeholder' => $input->getAttribute('placeholder'),
                    ];
                }
                $result['forms'][] = [
                    'action'  => $form->getAttribute('action'),
                    'method'  => $form->getAttribute('method') ?: 'GET',
                    'has_password' => $this->hasInputOfType($inputs, 'password'),
                    'has_file'    => $this->hasInputOfType($inputs, 'file'),
                    'input_count' => count($inputs),
                    'inputs'  => $inputs,
                ];
            }

            // 所有 script 标签
            $scripts = $dom->getElementsByTagName('script');
            foreach ($scripts as $script) {
                $result['script_count']++;
                $src = $script->getAttribute('src');
                if ($src) {
                    $result['scripts'][] = ['type' => 'external', 'src' => $src];
                } else {
                    $content = trim($script->textContent);
                    if (strlen($content) > 20) {
                        $result['scripts'][] = ['type' => 'inline', 'length' => strlen($content), 'preview' => substr($content, 0, 200)];
                    }
                }
            }

            // 外链 URL
            $links = $dom->getElementsByTagName('a');
            foreach ($links as $a) {
                $href = $a->getAttribute('href');
                if ($href && !str_starts_with($href, '#') && !str_starts_with($href, 'javascript:')) {
                    $result['external_urls'][] = [
                        'href' => $href,
                        'text' => trim($a->textContent),
                    ];
                }
            }

            // meta refresh 重定向
            $metas = $dom->getElementsByTagName('meta');
            foreach ($metas as $meta) {
                if (strtolower($meta->getAttribute('http-equiv')) === 'refresh') {
                    $result['redirects'][] = ['type' => 'meta', 'content' => $meta->getAttribute('content')];
                }
            }
        }
        libxml_clear_errors();

        // 重定向检测
        if (preg_match('/window\.location\.(href|replace)\s*=\s*[\'"]([^\'"]+)[\'"]/i', $body, $m)) {
            $result['redirects'][] = ['type' => 'js', 'target' => $m[2]];
        }

        // 模式匹配
        foreach ($this->suspiciousPatterns as $name => $pattern) {
            if (preg_match_all($pattern, $body, $matches, PREG_OFFSET_CAPTURE)) {
                $result['pattern_matches'][$name] = count($matches[0]);
            }
        }

        // 钓鱼关键字
        $lowerBody = strtolower($body);
        foreach ($this->phishingKeywords as $kw) {
            if (str_contains($lowerBody, strtolower($kw))) {
                $result['phishing_keywords'][] = $kw;
            }
        }

        // 生成风险
        $this->generateIssues($result);

        return $result;
    }

    private function hasInputOfType(array $inputs, string $type): bool
    {
        foreach ($inputs as $i) {
            if (strtolower($i['type'] ?? '') === strtolower($type)) return true;
        }
        return false;
    }

    private function generateIssues(array &$result): void
    {
        if (count($result['forms']) > 0) {
            foreach ($result['forms'] as $f) {
                if ($f['has_password']) {
                    $result['issues'][] = '页面包含密码输入表单';
                    break;
                }
            }
        }

        foreach ($result['pattern_matches'] as $name => $count) {
            if ($count > 0) {
                $result['issues'][] = "检测到可疑模式: {$name} ({$count} 处匹配)";
            }
        }

        if (count($result['phishing_keywords']) > 0) {
            $result['issues'][] = '页面包含钓鱼话术: ' . implode(' | ', $result['phishing_keywords']);
        }

        if (count($result['redirects']) > 0) {
            $result['issues'][] = '页面包含重定向行为（可能跳转钓鱼页面）';
        }

        // 表单 action 指向外部
        foreach ($result['forms'] as $f) {
            if (!empty($f['action']) && !str_starts_with($f['action'], '/') && !str_starts_with($f['action'], '#')) {
                $result['issues'][] = '表单数据提交到外部域名: ' . $f['action'];
            }
        }
    }
}
