<?php
/**
 * SSL/TLS 证书深度检测模块
 */
class SslChecker
{
    private const TIMEOUT = 8;

    public function check(string $host, int $port = 443): array
    {
        $result = [
            'certificate'     => null,
            'tls_version'    => null,
            'cipher'          => null,
            'cert_error'      => null,
            'cert_details'    => [],
            'cert_transparency' => null,
            'issues'          => [],
        ];

        // 尝试不同的 TLS 版本
        $contexts = [
            'TLSv1.3' => ['ssl' => ['min_version' => STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT, 'verify_peer' => false, 'verify_peer_name' => false]],
            'TLSv1.2' => ['ssl' => ['min_version' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT, 'max_version' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT, 'verify_peer' => false, 'verify_peer_name' => false]],
            'auto'    => ['ssl' => ['verify_peer' => false, 'verify_peer_name' => false]],
        ];

        $lastError = null;
        foreach ($contexts as $version => $ctxConfig) {
            $ctx = stream_context_create($ctxConfig);
            $fp = @stream_socket_client(
                'ssl://' . $host . ':' . $port,
                $errno, $errstr,
                self::TIMEOUT,
                STREAM_CLIENT_CONNECT,
                $ctx
            );

            if ($fp) {
                $meta = stream_get_meta_data($fp);
                $crypto = $meta['crypto'] ?? [];
                $result['tls_version'] = $crypto['protocol'] ?? $version;
                $result['cipher'] = $crypto['cipher_name'] ?? null;

                $cert = stream_socket_get_name($fp, true);
                if ($cert !== false) {
                    $parsed = openssl_x509_parse($cert);
                    if ($parsed) {
                        $result['certificate'] = [
                            'subject'    => $parsed['subject'] ?? null,
                            'issuer'     => $parsed['issuer'] ?? null,
                            'valid_from' => $parsed['validFrom_time_t'] ?? null,
                            'valid_to'   => $parsed['validTo_time_t'] ?? null,
                            'serial'     => $parsed['serialNumberHex'] ?? null,
                            'fingerprint'=> null,
                            'san'        => $parsed['subjectAltName'] ?? null,
                        ];

                        $now = time();
                        $daysLeft = ($parsed['validTo_time_t'] - $now) / 86400;
                        $result['cert_details']['days_remaining'] = round($daysLeft);
                        $result['cert_details']['is_expired'] = $daysLeft < 0;
                        $result['cert_details']['is_self_signed'] =
                            ($parsed['subject']['CN'] ?? '') === ($parsed['issuer']['CN'] ?? '');
                    }
                }
                fclose($fp);
                break;
            } else {
                $lastError = "{$version}: {$errstr}";
            }
        }

        if ($result['certificate'] === null) {
            $result['cert_error'] = $lastError ?? '无法建立 SSL 连接';
        }

        // 证书透明度查询 (crt.sh)
        $result['cert_transparency'] = $this->queryCrtSh($host);

        // 生成 SSL 相关风险
        $this->generateIssues($result);

        return $result;
    }

    private function queryCrtSh(string $host): array
    {
        $result = ['found' => false, 'cert_count' => 0, 'sample_domains' => []];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL        => 'https://crt.sh/?q=' . urlencode('%.' . $host) . '&output=json&limit=10',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT    => 8,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT  => 'URLChecker/1.0',
        ]);
        $resp = curl_exec($ch);
        curl_close($ch);

        if (!$resp) return $result;

        $data = @json_decode($resp, true);
        if (!is_array($data)) return $result;

        $result['found'] = true;
        $result['cert_count'] = count($data);

        $domains = [];
        foreach (array_slice($data, 0, 20) as $cert) {
            if (!empty($cert['name_value'])) {
                foreach (explode("\n", $cert['name_value']) as $d) {
                    $d = trim($d);
                    if ($d) $domains[$d] = true;
                }
            }
        }
        $result['sample_domains'] = array_keys($domains);

        return $result;
    }

    private function generateIssues(array &$result): void
    {
        if ($result['certificate'] === null) {
            $result['issues'][] = '无法获取 SSL 证书，TLS 握手可能被阻断或证书不存在';
            return;
        }

        $cert = $result['certificate'];
        $details = $result['cert_details'];

        if ($details['is_self_signed']) {
            $result['issues'][] = '证书为自签名证书，浏览器不被信任';
        }

        if ($details['is_expired']) {
            $result['issues'][] = 'SSL 证书已过期！';
        } elseif ($details['days_remaining'] < 30) {
            $result['issues'][] = 'SSL 证书即将过期（剩余 ' . $details['days_remaining'] . ' 天）';
        }

        // crt.sh 没记录但有证书 - 可疑
        if ($result['cert_transparency']['found'] === false) {
            $result['issues'][] = 'crt.sh 证书透明度日志中未找到该域名的历史证书记录（可疑）';
        }
    }
}
