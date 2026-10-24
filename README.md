# 🔒 URL Checker · 网站安全检测工具

一个用 PHP 实现的 **URL 安全检测 Web 应用**，输入任意网站链接，自动进行七维度深度分析，输出风险评分与详细评估报告。

> 在线自测：先在本地 `php -S` 起一个服务，浏览器打开即可使用。
>
> ⚠️ 本工具仅供安全自查 / 研究使用，不构成任何安全承诺。

---

## ✨ 功能特性

### 🔍 七维度深度检测

| 维度 | 权重 | 检测内容 |
|------|:----:|----------|
| **URL 结构分析** | 15% | Shannon 熵随机子域名/路径、短链识别、可疑关键字、子域名层数 |
| **DNS 配置** | 10% | NS / MX / AAAA / CNAME / DMARC / SPF / TXT、20+ 常见子域名枚举 |
| **连通性 & 端口** | 15% | TCP 8 个常用端口扫描、HTTPS/HTTP 响应、响应头 |
| **SSL/TLS 证书** | 15% | TLS 版本、加密套件、自签名检测、剩余有效期、crt.sh 历史证书 |
| **IP 画像** | 15% | 归属地 / ASN / ISP、云托管商标识、香港/俄罗斯等特殊地区标记 |
| **页面内容** | 20% | DOM 表单、密码输入、外链数、JS 可疑模式（keylogger/miner/eval）、钓鱼话术 |
| **安全响应头** | 10% | HSTS / CSP / X-Frame-Options / X-Content-Type-Options 等 7 项 |

### 🎯 反侦察识别（精准命中钓鱼/恶意站点）

- **随机子域名** — Shannon 熵 > 3.5 + 连续辅音链 + 数字混合
- **伞形子域名** — 同一 IP 上挂 5+ 子域名
- **主动断连** — TCP 端口可达但 HTTP 握手失败（gycoop.cn 就是典型）
- **证书透明度空白** — crt.sh 无任何历史记录
- **DNS 极简配置** — 无 MX / 无 DMARC / 无 SPF / 无 TXT

### 🛡️ 内置防护

- **SSRF 阻断**：禁止输入 IP、解析到内网 IP 自动拦截、协议白名单（http/https only）
- **频率限制**：Session 级 3 秒节流 + 每分钟 10 次上限
- **黑名单协议**：`php://` / `file://` / `data://` / `gopher://` / `dict://` / `ftp://`

### 📊 可视化报告

- **综合评分环** — 0-100 分、5 个风险等级（安全 / 低 / 中 / 高 / 高危）
- **雷达图** — 七维度评分一眼看出哪项拖后腿
- **风险标签** — 颜色编码快速定位（🔴高危 / 🟡警告 / 🔵信息）
- **问题清单** — 按严重程度排序，带来源模块

---

## 🛠️ 技术栈

- **PHP 8.2+**（测试环境 PHP 8.5）
- **原生 HTML + CSS + JavaScript**，前端零依赖（仅引入 Chart.js 用于雷达图）
- **核心扩展**：`curl` / `openssl` / `dom` / `json` / `mbstring` / `pcre`

---

## 🚀 快速开始

### 1. 克隆 & 启动

```bash
git clone git@github.com:SMTVCCC/url-checker.git
cd url-checker

# 内置 PHP 服务器（最简单）
php -S 0.0.0.0:8765 -t .

# 或指定端口
php -S localhost:8080 -t .
```

### 2. 浏览器访问

打开 http://localhost:8765/ ，输入任意 URL 即可检测。

### 3. 作为 API 使用

```bash
curl -X POST http://localhost:8765/api.php \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

返回完整 JSON：
```json
{
  "ok": true,
  "elapsed": 3.24,
  "url": "https://example.com/",
  "host": "example.com",
  "ips": ["104.20.23.154"],
  "modules": { "url_info": {...}, "dns": {...}, "connectivity": {...}, "ssl": {...} },
  "score": {
    "scores": {...},
    "overall": 75,
    "level": {"label": "低风险", "color": "#84cc16"},
    "tags": [...],
    "summary": "🟢 未检测到明显恶意特征..."
  }
}
```

### 4. 生产部署（推荐）

Apache / Nginx + PHP-FPM 部署：

```nginx
# Nginx 示例
server {
    listen 80;
    server_name your-domain.com;
    root /var/www/url-checker;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }

    # 禁止直接访问 includes 目录
    location ~ /includes/ { deny all; }
}
```

---

## 📁 项目结构

```
url-checker/
├── index.php                     # 前端页面（完整 UI）
├── api.php                       # AJAX 接口（返回 JSON）
├── includes/
│   ├── UrlParser.php             # URL 解析 + SSRF 防护 + 随机熵
│   ├── DnsChecker.php            # DNS 深度检测 + 子域名枚举
│   ├── ConnectivityChecker.php   # TCP 端口 + HTTP 响应 + 安全头
│   ├── SslChecker.php            # TLS 证书 + crt.sh 透明度
│   ├── IpProfiler.php            # IP 归属地 + ASN + 托管商
│   ├── ContentAnalyzer.php       # DOM 表单 + JS 可疑模式 + 钓鱼话术
│   └── ScoreEngine.php           # 七维度加权评分引擎
└── .gitignore
```

---

## 🧪 实测效果

| 目标 | 综合分 | 风险等级 | 命中标签 |
|------|:------:|:--------:|----------|
| `https://example.com` | 75 | 🟢 低风险 | 安全头缺失（真实情况） |
| `https://github.com` | 95 | 🟢 安全 | — |
| `https://3wk9tndk5.gycoop.cn/v3t9eq` | **47** | 🟠 中风险 | 🔴随机子域名 / 🟡伞形子域名 / 🟡无 DMARC |

---

## ⚠️ 局限性说明

1. **反侦察绕过**：部分攻击者服务器会对特定来源主动断连，后端拿到的结果也是超时/断开（这本身也是一个风险特征，本工具已识别）
2. **威胁情报**：未集成 VirusTotal / Shodan 等付费 API，如果你有 key，可以在 `IpProfiler` 中扩展
3. **内容深度**：后端只抓取响应前 3KB，前端浏览器渲染后的 DOM 不可见（需要无头浏览器才能完整分析）
4. **误报**：部分正规网站（如纯静态站）的 DNS 配置可能较简单，会触发轻度警告

---

## 📄 License

MIT
