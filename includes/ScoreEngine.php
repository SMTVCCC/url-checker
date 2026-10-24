<?php
/**
 * 综合评分引擎 - 汇总各模块结果，计算风险分
 */
class ScoreEngine
{
    /**
     * 综合分析并生成评分 + 标签 + 总结
     */
    public function analyze(array $data): array
    {
        $scores = [
            'url_structure'    => $this->scoreUrlStructure($data),
            'dns_config'       => $this->scoreDnsConfig($data),
            'connectivity'     => $this->scoreConnectivity($data),
            'ssl_certificate'  => $this->scoreSslCertificate($data),
            'ip_reputation'    => $this->scoreIpReputation($data),
            'content_risk'     => $this->scoreContentRisk($data),
            'security_headers' => $this->scoreSecurityHeaders($data),
        ];

        // 加权综合分 (0-100, 越低越危险)
        $weights = [
            'url_structure'    => 15,
            'dns_config'       => 10,
            'connectivity'     => 15,
            'ssl_certificate'  => 15,
            'ip_reputation'    => 15,
            'content_risk'     => 20,
            'security_headers' => 10,
        ];

        $overallScore = 0;
        foreach ($scores as $k => $v) {
            $overallScore += ($v / 100) * $weights[$k];
        }
        $overallScore = round($overallScore);

        // 风险等级
        $level = $this->riskLevel($overallScore);

        // 风险标签
        $tags = $this->generateTags($data, $scores);

        // 所有 issues 合并
        $allIssues = $this->collectAllIssues($data);

        // 总结
        $summary = $this->generateSummary($level, $tags, $allIssues);

        return [
            'scores'       => $scores,
            'weights'      => $weights,
            'overall'      => $overallScore,
            'level'        => $level,
            'tags'         => $tags,
            'all_issues'   => $allIssues,
            'summary'      => $summary,
        ];
    }

    // ========== 各维度评分 ==========

    private function scoreUrlStructure(array $d): int
    {
        $score = 100;
        $url = $d['url_info'] ?? [];

        if (($url['host_randomness']['high'] ?? false)) $score -= 25;
        if (($url['path_randomness']['high'] ?? false)) $score -= 20;
        if (($url['is_short_url'] ?? false)) $score -= 15;
        if (count($url['suspicious_keywords'] ?? []) > 2) $score -= 20;
        if (($url['subdomain_count'] ?? 0) >= 3) $score -= 10;

        return max(0, $score);
    }

    private function scoreDnsConfig(array $d): int
    {
        $score = 100;
        $dns = $d['dns'] ?? [];

        if (empty($dns['ns_records'] ?? [])) $score -= 30;
        if (empty($dns['mx_records'] ?? [])) $score -= 10;
        if ($dns['dmarc'] === null) $score -= 15;
        if ($dns['spf'] === null) $score -= 10;
        if (count($dns['txt_records'] ?? []) === 0) $score -= 10;
        if ((count($dns['subdomain_enum'] ?? [])) > 5) $score -= 20;

        return max(0, $score);
    }

    private function scoreConnectivity(array $d): int
    {
        $score = 100;
        $conn = $d['connectivity'] ?? [];
        $https = $conn['http_https'] ?? [];

        if (($https['http_code'] ?? 0) === 0) $score -= 50;
        if (($https['http_code'] ?? 0) >= 400 && ($https['http_code'] ?? 0) < 500) $score -= 20;
        if (($https['http_code'] ?? 0) >= 500) $score -= 15;

        // 所有端口都关闭
        $openPorts = 0;
        foreach ($conn['tcp_ports'] ?? [] as $p) {
            if (!empty($p['open'])) $openPorts++;
        }
        if ($openPorts === 0) $score -= 30;

        // 443 可达但 HTTP 失败 - 反侦察特征
        if (!empty($conn['tcp_ports'][443]['open']) && ($https['http_code'] ?? 0) === 0) {
            $score -= 30;
        }

        return max(0, $score);
    }

    private function scoreSslCertificate(array $d): int
    {
        $score = 100;
        $ssl = $d['ssl'] ?? [];
        $cert = $ssl['certificate'] ?? [];
        $details = $ssl['cert_details'] ?? [];

        if (empty($cert)) $score -= 50;
        if (!empty($details['is_self_signed'])) $score -= 30;
        if (!empty($details['is_expired'])) $score -= 40;
        if (($details['days_remaining'] ?? 999) < 30) $score -= 20;
        if (($ssl['cert_transparency']['found'] ?? true) === false) $score -= 20;

        return max(0, $score);
    }

    private function scoreIpReputation(array $d): int
    {
        $score = 80; // 默认基础分 (没有外部威胁情报 API)
        $ips = $d['ip_profile']['ips'] ?? [];

        foreach ($ips as $ip => $info) {
            $flags = $info['hosting_flags'] ?? [];
            foreach ($flags as $flag) {
                if (str_contains($flag, '香港')) $score -= 20;
                if (str_contains($flag, '俄罗斯')) $score -= 20;
            }
        }

        return max(0, $score);
    }

    private function scoreContentRisk(array $d): int
    {
        $score = 100;
        $content = $d['content'] ?? [];

        if (empty($content['has_body'])) $score -= 20; // 无法分析内容反而可疑

        if (count($content['phishing_keywords'] ?? []) > 0) $score -= 30;
        if (count($content['pattern_matches'] ?? []) > 0) $score -= 25;

        foreach ($content['forms'] ?? [] as $form) {
            if (!empty($form['has_password'])) $score -= 15;
            if (!empty($form['has_file'])) $score -= 10;
        }

        if (count($content['redirects'] ?? []) > 0) $score -= 15;

        return max(0, $score);
    }

    private function scoreSecurityHeaders(array $d): int
    {
        $score = 100;
        $headers = $d['connectivity']['security_headers'] ?? [];

        $mustHave = ['strict-transport-security', 'x-content-type-options', 'content-security-policy'];
        $niceHave = ['x-frame-options', 'referrer-policy', 'permissions-policy'];

        foreach ($mustHave as $h) {
            if (empty($headers[$h]['present'])) $score -= 15;
        }
        foreach ($niceHave as $h) {
            if (empty($headers[$h]['present'])) $score -= 8;
        }

        return max(0, $score);
    }

    // ========== 风险判定 ==========

    private function riskLevel(int $score): array
    {
        if ($score >= 80) return ['label' => '安全',   'color' => '#22c55e', 'bg' => 'bg-green-500'];
        if ($score >= 60) return ['label' => '低风险', 'color' => '#84cc16', 'bg' => 'bg-lime-500'];
        if ($score >= 40) return ['label' => '中风险', 'color' => '#f59e0b', 'bg' => 'bg-amber-500'];
        if ($score >= 20) return ['label' => '高风险', 'color' => '#ef4444', 'bg' => 'bg-red-500'];
        return ['label' => '高危', 'color' => '#dc2626', 'bg' => 'bg-red-700'];
    }

    private function generateTags(array $d, array $scores): array
    {
        $tags = [];
        $url = $d['url_info'] ?? [];
        $ssl = $d['ssl'] ?? [];
        $conn = $d['connectivity'] ?? [];
        $dns = $d['dns'] ?? [];
        $content = $d['content'] ?? [];

        // URL 结构
        if (($url['host_randomness']['high'] ?? false)) $tags[] = ['type' => 'danger', 'text' => '随机子域名'];
        if (($url['path_randomness']['high'] ?? false)) $tags[] = ['type' => 'danger', 'text' => '随机路径'];
        if (($url['is_short_url'] ?? false)) $tags[] = ['type' => 'warning', 'text' => '短链服务'];

        // DNS
        if (count($dns['subdomain_enum'] ?? []) > 5) $tags[] = ['type' => 'warning', 'text' => '伞形子域名'];
        if ($dns['dmarc'] === null) $tags[] = ['type' => 'warning', 'text' => '无 DMARC'];

        // SSL
        if (!empty($ssl['cert_details']['is_self_signed'])) $tags[] = ['type' => 'danger', 'text' => '自签名证书'];
        if (!empty($ssl['cert_details']['is_expired'])) $tags[] = ['type' => 'danger', 'text' => '证书过期'];
        if (!empty($ssl['certificate']) && ($ssl['cert_transparency']['found'] ?? true) === false) {
            $tags[] = ['type' => 'danger', 'text' => '无公开证书记录'];
        }

        // 连通性 - 最关键的反侦察特征
        $https = $conn['http_https'] ?? [];
        if (($https['http_code'] ?? 0) === 0 && !empty($conn['tcp_ports'][443]['open'])) {
            $tags[] = ['type' => 'danger', 'text' => '主动断连'];
            $tags[] = ['type' => 'danger', 'text' => '反侦察'];
        }

        // 内容
        if (count($content['phishing_keywords'] ?? []) > 0) $tags[] = ['type' => 'danger', 'text' => '含钓鱼话术'];
        foreach ($content['forms'] ?? [] as $f) {
            if (!empty($f['has_password'])) { $tags[] = ['type' => 'danger', 'text' => '含密码表单']; break; }
        }
        if (count($content['pattern_matches'] ?? []) > 0) $tags[] = ['type' => 'danger', 'text' => '可疑脚本'];

        return $tags;
    }

    private function collectAllIssues(array $d): array
    {
        $all = [];
        $sections = ['url_info', 'dns', 'connectivity', 'ssl', 'content'];
        $map = [
            'url_info'     => ['errors', 'warnings'],
            'dns'          => ['issues'],
            'connectivity' => ['issues'],
            'ssl'          => ['issues'],
            'content'      => ['issues'],
        ];

        foreach ($sections as $section) {
            if (!isset($d[$section])) continue;
            foreach ($map[$section] as $key) {
                foreach ($d[$section][$key] ?? [] as $issue) {
                    $all[] = ['section' => $section, 'message' => $issue];
                }
            }
        }

        return $all;
    }

    private function generateSummary(array $level, array $tags, array $issues): string
    {
        $counts = array_count_values(array_column($tags, 'type'));
        $dangerCount = $counts['danger'] ?? 0;
        $warningCount = $counts['warning'] ?? 0;

        $parts = [];

        if ($dangerCount >= 2) {
            $parts[] = '🔴 检测到多个高危特征，强烈建议谨慎对待，不要在该页面输入任何个人信息';
        } elseif ($dangerCount === 1) {
            $parts[] = '🟠 检测到高危特征，存在一定安全风险，建议谨慎访问';
        } elseif ($warningCount >= 3) {
            $parts[] = '🟡 检测到多项警告特征，建议通过官方渠道核实该网站的真实性';
        } else {
            $parts[] = '🟢 未检测到明显恶意特征，但仍建议保持基本安全意识';
        }

        if ($warningCount > 0) {
            $parts[] = '共发现 ' . $dangerCount . ' 个高危点、' . $warningCount . ' 个警告点、' . count($issues) . ' 条注意事项';
        }

        return implode("\n", $parts);
    }
}
