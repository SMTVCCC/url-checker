<?php
/**
 * DNS 深度检测模块
 */
class DnsChecker
{
    private const TIMEOUT = 3;

    public function check(string $host, array $ips): array
    {
        $result = [
            'a_records'     => $ips,
            'mx_records'    => [],
            'ns_records'    => [],
            'txt_records'   => [],
            'aaaa_records'  => [],
            'cname'         => null,
            'subdomain_enum'=> [],
            'dmarc'         => null,
            'spf'           => null,
            'dnssec'        => false,
            'issues'        => [],
        ];

        // NS 记录
        $ns = @dns_get_record($host, DNS_NS);
        if ($ns !== false) {
            foreach ($ns as $r) {
                $result['ns_records'][] = $r['target'];
            }
        }

        // MX 记录
        $mx = @dns_get_record($host, DNS_MX);
        if ($mx !== false) {
            foreach ($mx as $r) {
                $result['mx_records'][] = [
                    'host' => $r['host'],
                    'priority' => $r['pri'],
                ];
            }
        }

        // TXT 记录
        $txt = @dns_get_record($host, DNS_TXT);
        if ($txt !== false) {
            foreach ($txt as $r) {
                $result['txt_records'][] = $r['txt'];
            }
        }

        // AAAA
        $aaaa = @dns_get_record($host, DNS_AAAA);
        if ($aaaa !== false) {
            foreach ($aaaa as $r) {
                $result['aaaa_records'][] = $r['ipv6'];
            }
        }

        // CNAME
        $cname = @dns_get_record($host, DNS_CNAME);
        if ($cname !== false && !empty($cname)) {
            $result['cname'] = $cname[0]['target'];
        }

        // DMARC 检查
        $dmarcRecords = @dns_get_record('_dmarc.' . $host, DNS_TXT);
        if ($dmarcRecords !== false) {
            foreach ($dmarcRecords as $r) {
                if (str_starts_with($r['txt'], 'v=DMARC1')) {
                    $result['dmarc'] = $r['txt'];
                    break;
                }
            }
        }

        // SPF 检查
        foreach ($result['txt_records'] as $t) {
            if (str_starts_with($t, 'v=spf1')) {
                $result['spf'] = $t;
                break;
            }
        }

        // 子域名枚举 (top 20 common)
        $commonSubs = [
            'www', 'mail', 'api', 'admin', 'login', 'blog', 'shop',
            'dev', 'staging', 'test', 'cdn', 'static', 'img', 'app',
            'm', 'mobile', 'secure', 'support', 'ftp', 'vpn',
        ];
        foreach ($commonSubs as $sub) {
            $subHost = $sub . '.' . $host;
            $resolved = @gethostbyname($subHost);
            if ($resolved !== $subHost && $resolved !== false) {
                $result['subdomain_enum'][$sub] = $resolved;
            }
        }

        // 生成 DNS 相关风险
        if (empty($result['ns_records'])) {
            $result['issues'][] = '未检测到 NS 记录，DNS 配置不完整';
        }
        if (empty($result['mx_records'])) {
            $result['issues'][] = '未检测到 MX 记录（无邮件服务）';
        }
        if ($result['dmarc'] === null) {
            $result['issues'][] = '未配置 DMARC 记录（邮件伪造防护缺失）';
        }
        if ($result['spf'] === null) {
            $result['issues'][] = '未配置 SPF 记录（邮件伪造防护缺失）';
        }
        if (empty($result['txt_records'])) {
            $result['issues'][] = '无任何 TXT 记录，域名配置极简';
        }
        // 同一 IP 上挂了太多子域名（>5）
        $subCount = count($result['subdomain_enum']);
        if ($subCount > 5) {
            $result['issues'][] = "同一域名下发现 {$subCount} 个子域名指向同一 IP（伞形结构特征）";
        }

        return $result;
    }
}
