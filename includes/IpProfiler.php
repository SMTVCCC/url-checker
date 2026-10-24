<?php
/**
 * IP 画像模块 - 获取 IP 归属地、ASN、托管商信息
 */
class IpProfiler
{
    public function check(array $ips): array
    {
        $result = ['ips' => [], 'api_error' => null];

        foreach ($ips as $ip) {
            $result['ips'][$ip] = $this->queryIpApi($ip);
        }

        return $result;
    }

    private function queryIpApi(string $ip): array
    {
        // 优先用 ip-api.com (免费、无 key、JSON)
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL        => "http://ip-api.com/json/{$ip}?fields=status,message,country,regionName,city,isp,org,as,hosting,proxy,mobile",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT    => 5,
        ]);
        $resp = curl_exec($ch);
        curl_close($ch);

        $data = [];
        if ($resp) {
            $data = @json_decode($resp, true);
        }

        // 退回到 ipinfo.io
        if (empty($data) || ($data['status'] ?? '') === 'fail') {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL        => "https://ipinfo.io/{$ip}/json",
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT    => 5,
                CURLOPT_SSL_VERIFYPEER => false,
            ]);
            $resp = curl_exec($ch);
            curl_close($ch);

            if ($resp) {
                $data2 = @json_decode($resp, true);
                if (!empty($data2)) {
                    $data = [
                        'status'      => 'success',
                        'country'     => $data2['country'] ?? null,
                        'regionName'  => $data2['region'] ?? null,
                        'city'        => $data2['city'] ?? null,
                        'isp'         => null,
                        'org'         => $data2['org'] ?? null,
                        'as'          => $data2['asn'] ?? null,
                        'loc'         => $data2['loc'] ?? null,
                    ];
                }
            }
        }

        // 识别托管/ISP 特征
        $hostingFlags = $this->identifyHosting($data);

        return array_merge($data, ['hosting_flags' => $hostingFlags]);
    }

    private function identifyHosting(array $data): array
    {
        $flags = [];
        $text = strtolower(implode(' ', [
            $data['isp'] ?? '',
            $data['org'] ?? '',
            $data['as'] ?? '',
        ]));

        $cloudProviders = [
            'alibaba'      => '阿里云',
            'tencent'      => '腾讯云',
            'aws'          => 'AWS',
            'amazon'       => 'AWS',
            'google'       => 'Google Cloud',
            'cloudflare'   => 'Cloudflare',
            'microsoft'    => 'Azure',
            'azure'        => 'Azure',
            'vultr'        => 'Vultr',
            'digitalocean' => 'DigitalOcean',
            'linode'       => 'Linode',
            'he.net'       => 'Hurricane Electric',
        ];

        foreach ($cloudProviders as $pattern => $name) {
            if (str_contains($text, $pattern)) {
                $flags[] = "云托管: {$name}";
            }
        }

        // 香港 / 特殊地区警告
        $country = strtolower($data['country'] ?? '');
        if ($country === 'hk' || $country === 'hong kong') {
            $flags[] = '托管在香港（诈骗/钓鱼活动常见地区）';
        }
        if ($country === 'ru') {
            $flags[] = '托管在俄罗斯（谨慎）';
        }
        if ($country === 'cn') {
            $flags[] = '托管在中国大陆';
        }

        return $flags;
    }
}
