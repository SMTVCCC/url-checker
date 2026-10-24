<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔒 URL 安全检测工具 - 网站风险评估</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh;
    color: #1a1a2e;
    padding: 20px;
  }
  .container { max-width: 1100px; margin: 0 auto; }

  /* Header */
  header { text-align: center; padding: 40px 20px 30px; color: #fff; }
  header h1 { font-size: 2.2rem; margin-bottom: 10px; font-weight: 700; text-shadow: 0 2px 10px rgba(0,0,0,0.2); }
  header p { font-size: 1.05rem; opacity: 0.9; }

  /* Input Box */
  .input-section {
    background: #fff;
    border-radius: 16px;
    padding: 30px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.15);
    margin-bottom: 24px;
  }
  .input-row { display: flex; gap: 12px; }
  .input-row input {
    flex: 1;
    padding: 14px 18px;
    font-size: 1rem;
    border: 2px solid #e0e0e0;
    border-radius: 10px;
    outline: none;
    transition: border-color 0.2s;
  }
  .input-row input:focus { border-color: #667eea; }
  .input-row button {
    padding: 14px 32px;
    font-size: 1rem;
    font-weight: 600;
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: #fff;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    transition: transform 0.15s, box-shadow 0.15s;
  }
  .input-row button:hover { transform: translateY(-1px); box-shadow: 0 4px 15px rgba(102,126,234,0.4); }
  .input-row button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
  .quick-links { margin-top: 14px; display: flex; gap: 8px; flex-wrap: wrap; }
  .quick-links span { font-size: 0.85rem; color: #888; }
  .quick-links button {
    padding: 4px 12px;
    font-size: 0.8rem;
    background: #f3f4f6;
    border: 1px solid #e5e7eb;
    border-radius: 20px;
    cursor: pointer;
    transition: all 0.15s;
  }
  .quick-links button:hover { background: #e0e7ff; color: #4f46e5; border-color: #c7d2fe; }

  /* Loading */
  .loading { display: none; text-align: center; padding: 40px; }
  .loading.active { display: block; }
  .spinner {
    width: 48px; height: 48px; border: 4px solid #e0e0e0;
    border-top-color: #667eea; border-radius: 50%;
    animation: spin 1s linear infinite; margin: 0 auto 16px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .loading p { color: #666; font-size: 0.95rem; }
  .progress {
    margin-top: 20px; background: #f0f0f0; border-radius: 10px;
    height: 6px; overflow: hidden; max-width: 400px; margin-left: auto; margin-right: auto;
  }
  .progress-bar {
    height: 100%; background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 10px; transition: width 0.3s; width: 0%;
  }
  .progress-text { font-size: 0.8rem; color: #888; margin-top: 8px; }

  /* Error */
  .error-box {
    display: none; background: #fef2f2; border: 1px solid #fecaca; color: #991b1b;
    padding: 16px 20px; border-radius: 10px; margin-bottom: 20px;
  }
  .error-box.active { display: block; }
  .error-box strong { display: block; margin-bottom: 6px; }

  /* Result */
  .result { display: none; }
  .result.active { display: block; }

  /* Score Card */
  .score-card {
    background: #fff; border-radius: 16px; padding: 30px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.15); margin-bottom: 24px;
  }
  .score-header { display: flex; align-items: center; gap: 30px; flex-wrap: wrap; }
  .score-circle {
    position: relative; width: 160px; height: 160px; flex-shrink: 0;
  }
  .score-circle svg { transform: rotate(-90deg); }
  .score-circle .score-num {
    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
    font-size: 2.8rem; font-weight: 800;
  }
  .score-info { flex: 1; min-width: 200px; }
  .score-info .label { font-size: 1rem; color: #666; margin-bottom: 6px; }
  .score-info .level { font-size: 2rem; font-weight: 800; margin-bottom: 10px; }
  .score-info .summary { font-size: 0.95rem; color: #555; line-height: 1.6; white-space: pre-line; }
  .score-meta {
    display: flex; gap: 14px; margin-top: 14px; flex-wrap: wrap;
  }
  .score-meta .meta-item {
    background: #f8fafc; border: 1px solid #e2e8f0;
    padding: 6px 14px; border-radius: 20px; font-size: 0.85rem; color: #475569;
  }

  /* Tags */
  .tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
  .tag {
    padding: 5px 14px; border-radius: 20px; font-size: 0.82rem; font-weight: 600;
  }
  .tag.danger { background: #fee2e2; color: #b91c1c; border: 1px solid #fecaca; }
  .tag.warning { background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }
  .tag.info { background: #dbeafe; color: #1d4ed8; border: 1px solid #bfdbfe; }

  /* Radar */
  .radar-container {
    background: #fff; border-radius: 16px; padding: 24px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.15); margin-bottom: 24px;
    height: 420px; position: relative;
  }

  /* Details sections */
  .details { display: grid; gap: 20px; }
  .section {
    background: #fff; border-radius: 16px; padding: 24px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
  }
  .section h3 {
    font-size: 1.1rem; font-weight: 700; margin-bottom: 16px;
    padding-bottom: 10px; border-bottom: 2px solid #f1f5f9;
    display: flex; align-items: center; gap: 8px;
  }
  .section h3 .icon { font-size: 1.2rem; }
  .section-grid { display: grid; gap: 10px; }
  .kv { display: flex; justify-content: space-between; font-size: 0.9rem; padding: 6px 0; border-bottom: 1px dashed #f1f5f9; }
  .kv:last-child { border-bottom: none; }
  .kv .k { color: #64748b; }
  .kv .v { color: #1e293b; font-weight: 500; word-break: break-all; text-align: right; max-width: 60%; }
  .kv .v.bad { color: #dc2626; }
  .kv .v.warn { color: #d97706; }
  .kv .v.good { color: #059669; }

  /* Port grid */
  .port-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 8px; }
  .port-box {
    padding: 10px; border-radius: 8px; text-align: center; font-size: 0.8rem;
  }
  .port-box.open { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
  .port-box.closed { background: #f1f5f9; color: #94a3b8; border: 1px solid #e2e8f0; }
  .port-box .port-num { font-size: 1.1rem; font-weight: 700; }
  .port-box .port-label { font-size: 0.7rem; opacity: 0.8; margin-top: 2px; }

  /* Headers */
  .header-check { padding: 8px 0; border-bottom: 1px dashed #f1f5f9; display: flex; justify-content: space-between; align-items: center; }
  .header-check:last-child { border: none; }
  .header-name { font-weight: 600; font-size: 0.9rem; }
  .header-desc { font-size: 0.75rem; color: #94a3b8; }
  .header-status { font-size: 0.8rem; padding: 3px 10px; border-radius: 10px; }
  .header-status.present { background: #dcfce7; color: #15803d; }
  .header-status.missing { background: #fee2e2; color: #b91c1c; }

  /* Issues list */
  .issues-list { list-style: none; }
  .issues-list li {
    padding: 10px 14px; border-radius: 8px; margin-bottom: 8px;
    font-size: 0.88rem; display: flex; gap: 10px;
  }
  .issues-list li.danger { background: #fef2f2; border-left: 4px solid #ef4444; color: #991b1b; }
  .issues-list li.warning { background: #fffbeb; border-left: 4px solid #f59e0b; color: #92400e; }
  .issues-list li.info { background: #eff6ff; border-left: 4px solid #3b82f6; color: #1e40af; }
  .issues-list .ic { font-size: 1.1rem; flex-shrink: 0; }
  .issues-list .src { font-size: 0.75rem; opacity: 0.6; margin-top: 3px; }

  /* Forms */
  .form-card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 12px; border-radius: 8px; margin-bottom: 10px; }
  .form-card .form-action { font-size: 0.82rem; color: #64748b; word-break: break-all; }
  .form-card .form-action.bad { color: #dc2626; font-weight: 600; }
  .form-inputs { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }
  .form-inputs .inp { background: #fff; border: 1px solid #cbd5e1; border-radius: 4px; padding: 3px 8px; font-size: 0.75rem; color: #475569; }
  .form-inputs .inp.password { border-color: #ef4444; color: #dc2626; background: #fef2f2; }

  /* Expandable */
  .collapsible { }
  .collapsible summary { cursor: pointer; padding: 8px 0; font-weight: 600; color: #475569; font-size: 0.9rem; }
  .collapsible summary:hover { color: #1e293b; }

  footer {
    text-align: center; padding: 30px; color: rgba(255,255,255,0.7);
    font-size: 0.85rem;
  }

  @media (max-width: 600px) {
    header h1 { font-size: 1.6rem; }
    .score-header { flex-direction: column; text-align: center; }
    .score-info .meta-item { justify-content: center; }
  }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔒 URL 安全检测</h1>
    <p>输入任意网站链接，快速评估风险等级，识别钓鱼/诈骗/恶意站点</p>
  </header>

  <div class="input-section">
    <div class="input-row">
      <input id="urlInput" type="text" placeholder="输入要检测的 URL，例如 https://example.com" autocomplete="off" spellcheck="false">
      <button id="checkBtn" onclick="startCheck()">🚀 开始检测</button>
    </div>
    <div class="quick-links">
      <span>试试: </span>
      <button onclick="document.getElementById('urlInput').value='https://www.baidu.com';startCheck()">百度 ✅</button>
      <button onclick="document.getElementById('urlInput').value='https://github.com';startCheck()">GitHub ✅</button>
      <button onclick="document.getElementById('urlInput').value='https://3wk9tndk5.gycoop.cn/v3t9eq';startCheck()">gycoop ⚠️</button>
      <button onclick="document.getElementById('urlInput').value='https://example.com';startCheck()">example.com ✅</button>
    </div>
  </div>

  <div id="loading" class="loading">
    <div class="spinner"></div>
    <p id="loadingText">正在检测中...</p>
    <div class="progress"><div id="progressBar" class="progress-bar"></div></div>
    <p class="progress-text" id="progressText">URL 解析中</p>
  </div>

  <div id="errorBox" class="error-box">
    <strong>❌ 检测失败</strong>
    <span id="errorMsg"></span>
  </div>

  <div id="result" class="result">
    <div class="score-card">
      <div class="score-header">
        <div class="score-circle">
          <svg width="160" height="160">
            <circle cx="80" cy="80" r="70" stroke="#e5e7eb" stroke-width="12" fill="none"/>
            <circle id="scoreRing" cx="80" cy="80" r="70" stroke="#667eea" stroke-width="12" fill="none" stroke-linecap="round" stroke-dasharray="440" stroke-dashoffset="440"/>
          </svg>
          <div id="scoreNum" class="score-num">--</div>
        </div>
        <div class="score-info">
          <div class="label">综合安全评分</div>
          <div id="scoreLevel" class="level">--</div>
          <div id="scoreSummary" class="summary"></div>
          <div id="scoreTags" class="tags"></div>
          <div class="score-meta">
            <div class="meta-item">🌐 <span id="metaHost">--</span></div>
            <div class="meta-item">📡 <span id="metaIP">--</span></div>
            <div class="meta-item">⏱️ <span id="metaTime">--</span></div>
          </div>
        </div>
      </div>
    </div>

    <div class="radar-container">
      <canvas id="radarChart"></canvas>
    </div>

    <div class="details">
      <div class="section">
        <h3><span class="icon">⚠️</span> 风险提示与发现</h3>
        <ul id="issuesList" class="issues-list"></ul>
      </div>

      <div class="section">
        <h3><span class="icon">🔗</span> URL 结构分析</h3>
        <div id="urlSection" class="section-grid"></div>
      </div>

      <div class="section">
        <h3><span class="icon">🖥️</span> DNS 配置</h3>
        <div id="dnsSection" class="section-grid"></div>
      </div>

      <div class="section">
        <h3><span class="icon">📡</span> 连通性 & 端口</h3>
        <div id="connSection"></div>
      </div>

      <div class="section">
        <h3><span class="icon">🔐</span> SSL/TLS 证书</h3>
        <div id="sslSection" class="section-grid"></div>
      </div>

      <div class="section">
        <h3><span class="icon">📍</span> IP 画像</h3>
        <div id="ipSection" class="section-grid"></div>
      </div>

      <div class="section">
        <h3><span class="icon">📄</span> 页面内容分析</h3>
        <div id="contentSection"></div>
      </div>

      <div class="section">
        <h3><span class="icon">🛡️</span> HTTP 安全响应头</h3>
        <div id="headersSection"></div>
      </div>
    </div>
  </div>

  <footer>
    ⚠️ 本工具仅供安全自查使用，不构成任何安全承诺 · 检测结果仅供参考
  </footer>
</div>

<script>
const STEPS = [
  'URL 解析与 SSRF 防护',
  'DNS 深度检测',
  'TCP 端口 & HTTP 响应',
  'SSL/TLS 证书分析',
  'IP 归属地查询',
  '页面内容扫描',
  '综合评分引擎'
];

let currentStepIdx = 0;
let stepTimer = null;

function startCheck() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) { alert('请输入 URL'); return; }

  document.getElementById('result').classList.remove('active');
  document.getElementById('errorBox').classList.remove('active');
  document.getElementById('loading').classList.add('active');
  document.getElementById('checkBtn').disabled = true;
  document.getElementById('checkBtn').textContent = '检测中...';

  // 进度动画
  currentStepIdx = 0;
  updateStepText();
  stepTimer = setInterval(() => {
    currentStepIdx = Math.min(currentStepIdx + 1, STEPS.length - 1);
    updateStepText();
  }, 800);

  fetch('api.php', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
  .then(r => r.json())
  .then(data => {
    clearInterval(stepTimer);
    document.getElementById('loading').classList.remove('active');
    document.getElementById('checkBtn').disabled = false;
    document.getElementById('checkBtn').textContent = '🚀 开始检测';

    if (!data.ok) {
      document.getElementById('errorMsg').textContent = data.error || '未知错误';
      document.getElementById('errorBox').classList.add('active');
      return;
    }
    renderResult(data);
  })
  .catch(err => {
    clearInterval(stepTimer);
    document.getElementById('loading').classList.remove('active');
    document.getElementById('checkBtn').disabled = false;
    document.getElementById('checkBtn').textContent = '🚀 开始检测';
    document.getElementById('errorMsg').textContent = '网络错误: ' + err.message;
    document.getElementById('errorBox').classList.add('active');
  });
}

function updateStepText() {
  const pct = Math.round((currentStepIdx / STEPS.length) * 100);
  document.getElementById('progressBar').style.width = pct + '%';
  document.getElementById('progressText').textContent = STEPS[currentStepIdx];
}

// ===== Rendering =====

function renderResult(d) {
  document.getElementById('result').classList.add('active');
  const s = d.score;

  // 分数环
  const ring = document.getElementById('scoreRing');
  const circumference = 2 * Math.PI * 70;
  ring.setAttribute('stroke-dasharray', circumference);
  ring.setAttribute('stroke-dashoffset', circumference - (s.overall / 100) * circumference);
  ring.setAttribute('stroke', s.level.color);
  document.getElementById('scoreNum').textContent = s.overall;
  document.getElementById('scoreNum').style.color = s.level.color;
  document.getElementById('scoreLevel').textContent = s.level.label;
  document.getElementById('scoreLevel').style.color = s.level.color;
  document.getElementById('scoreSummary').textContent = s.summary;

  // 元信息
  document.getElementById('metaHost').textContent = d.host;
  document.getElementById('metaIP').textContent = d.ips.join(', ');
  document.getElementById('metaTime').textContent = d.elapsed + 's';

  // 标签
  const tagsDiv = document.getElementById('scoreTags');
  tagsDiv.innerHTML = '';
  s.tags.forEach(t => {
    const el = document.createElement('span');
    el.className = 'tag ' + t.type;
    el.textContent = t.text;
    tagsDiv.appendChild(el);
  });

  // 雷达图
  drawRadar(s.scores);

  // 各 section
  renderIssues(s.all_issues);
  renderUrl(d.modules.url_info);
  renderDns(d.modules.dns);
  renderConn(d.modules.connectivity);
  renderSsl(d.modules.ssl);
  renderIp(d.modules.ip_profile);
  renderContent(d.modules.content);
  renderHeaders(d.modules.connectivity.security_headers);

  // 滚动到结果
  setTimeout(() => document.getElementById('result').scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

let radarChart = null;
function drawRadar(scores) {
  const ctx = document.getElementById('radarChart').getContext('2d');
  if (radarChart) radarChart.destroy();

  radarChart = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: ['URL 结构', 'DNS 配置', '连通性', 'SSL 证书', 'IP 画像', '页面内容', '安全头'],
      datasets: [{
        label: '安全评分 (0-100)',
        data: [
          scores.url_structure,
          scores.dns_config,
          scores.connectivity,
          scores.ssl_certificate,
          scores.ip_reputation,
          scores.content_risk,
          scores.security_headers,
        ],
        fill: true,
        backgroundColor: 'rgba(102, 126, 234, 0.25)',
        borderColor: 'rgba(102, 126, 234, 1)',
        pointBackgroundColor: 'rgba(102, 126, 234, 1)',
        pointRadius: 5,
        pointHoverRadius: 7,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0, max: 100,
          ticks: { stepSize: 20, backdropColor: 'transparent' },
          grid: { color: '#e5e7eb' },
          pointLabels: { font: { size: 13 }, color: '#374151' }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ' 安全度: ' + ctx.raw + '/100 (越高越安全)'
          }
        }
      }
    }
  });
}

function renderIssues(issues) {
  const ul = document.getElementById('issuesList');
  ul.innerHTML = '';
  if (!issues || issues.length === 0) {
    ul.innerHTML = '<li class="info"><span class="ic">✅</span>未发现明显风险点</li>';
    return;
  }
  issues.forEach(i => {
    const li = document.createElement('li');
    const isDanger = /SSL.*无法|主动断连|随机|自签名|过期|钓鱼|密码表单|证书不|SSRF/.test(i.message);
    const isWarn = /缺失|极简|伞形|DMARC|SPF|无邮件|无法获取/.test(i.message);
    li.className = isDanger ? 'danger' : (isWarn ? 'warning' : 'info');
    li.innerHTML = '<span class="ic">' + (li.className === 'danger' ? '🔴' : (li.className === 'warning' ? '🟡' : '🔵')) + '</span>' +
      '<div><div>' + i.message + '</div><div class="src">来源: ' + i.section + '</div></div>';
    ul.appendChild(li);
  });
}

function renderUrl(u) {
  const sec = document.getElementById('urlSection');
  sec.innerHTML = kvHtml([
    ['检测 URL', u.full_url, ''],
    ['Host', u.host, ''],
    ['Scheme', u.scheme + '://', ''],
    ['子域名层数', u.subdomain_count, u.subdomain_count >= 3 ? 'warn' : ''],
    ['Host 随机度 (熵)', u.host_randomness.entropy + ' / 8', u.host_randomness.high ? 'bad' : 'good'],
    ['Path 随机度 (熵)', u.path_randomness.entropy + ' / 8', u.path_randomness.high ? 'bad' : 'good'],
    ['Host 高熵 (随机特征)', u.host_randomness.high ? '⚠️ 是' : '✅ 否', u.host_randomness.high ? 'bad' : 'good'],
    ['Path 高熵 (随机特征)', u.path_randomness.high ? '⚠️ 是' : '✅ 否', u.path_randomness.high ? 'bad' : 'good'],
    ['是否短链服务', u.is_short_url ? '⚠️ 是' : '✅ 否', u.is_short_url ? 'warn' : 'good'],
    ['可疑关键字', u.suspicious_keywords.length ? u.suspicious_keywords.join(', ') : '无', u.suspicious_keywords.length ? 'warn' : 'good'],
  ]);
}

function renderDns(d) {
  const rows = [
    ['A 记录 (IP)', (d.a_records || []).join(', ') || '无', (!d.a_records || !d.a_records.length) ? 'bad' : ''],
    ['NS 记录', (d.ns_records || []).join(', ') || '无', (!d.ns_records || !d.ns_records.length) ? 'bad' : ''],
    ['MX 记录', d.mx_records && d.mx_records.length ? d.mx_records.map(m => m.host).join(', ') : '无', (!d.mx_records || !d.mx_records.length) ? 'warn' : ''],
    ['TXT 记录数', (d.txt_records || []).length, (!d.txt_records || !d.txt_records.length) ? 'warn' : 'good'],
    ['AAAA (IPv6)', (d.aaaa_records || []).join(', ') || '无', ''],
    ['CNAME', d.cname || '无', ''],
    ['DMARC', d.dmarc ? '✅ ' + d.dmarc.substring(0, 50) : '❌ 未配置', d.dmarc ? 'good' : 'warn'],
    ['SPF', d.spf ? '✅ ' + d.spf.substring(0, 50) : '❌ 未配置', d.spf ? 'good' : 'warn'],
    ['子域名枚举数', (d.subdomain_enum ? Object.keys(d.subdomain_enum).length : 0), (d.subdomain_enum && Object.keys(d.subdomain_enum).length > 5) ? 'warn' : ''],
  ];
  const html = kvHtml(rows);

  if (d.subdomain_enum && Object.keys(d.subdomain_enum).length) {
    html += '<details class="collapsible"><summary>📋 枚举到的子域名列表</summary><div class="section-grid" style="margin-top:10px">';
    Object.entries(d.subdomain_enum).forEach(([sub, ip]) => {
      html += '<div class="kv"><span class="k">' + sub + '.</span><span class="v">' + ip + '</span></div>';
    });
    html += '</div></details>';
  }

  document.getElementById('dnsSection').innerHTML = html;
}

function renderConn(c) {
  // 端口
  let portHtml = '<div style="margin-bottom:16px"><div style="font-weight:600;margin-bottom:8px">TCP 端口可达性</div><div class="port-grid">';
  const portNames = {21:'FTP', 22:'SSH', 80:'HTTP', 443:'HTTPS', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 3000:'Dev', 5000:'Dev'};
  Object.entries(c.tcp_ports || {}).forEach(([port, info]) => {
    portHtml += '<div class="port-box ' + (info.open ? 'open' : 'closed') + '">';
    portHtml += '<div class="port-num">' + port + '</div>';
    portHtml += '<div class="port-label">' + (portNames[port] || '') + (info.open ? ' · ' + info.latency_ms + 'ms' : '') + '</div>';
    portHtml += '</div>';
  });
  portHtml += '</div></div>';

  // HTTPS 响应
  const h = c.http_https || {};
  portHtml += '<div style="margin-top:16px" class="section-grid">';
  portHtml += kvHtml([
    ['HTTPS 状态码', h.http_code || '0 (连接失败)', (!h.http_code || h.http_code === 0) ? 'bad' : (h.http_code >= 400 ? 'warn' : 'good')],
    ['HTTPS 耗时', h.total_time + 's', ''],
    ['HTTP 明文状态码', (c.http_plain || {}).http_code || '未检测', ''],
    ['重定向 URL', h.redirect_url || '无', ''],
    ['服务器', h.headers && h.headers.server ? h.headers.server : '未暴露', ''],
  ]);
  portHtml += '</div>';

  document.getElementById('connSection').innerHTML = portHtml;
}

function renderSsl(s) {
  const cert = s.certificate || {};
  const det = s.cert_details || {};
  const days = det.days_remaining;

  const rows = [
    ['TLS 版本', s.tls_version || '未知', s.tls_version ? 'good' : 'bad'],
    ['加密套件', s.cipher || '未知', s.cipher ? '' : 'bad'],
  ];

  if (cert.subject) {
    rows.push(['证书主题', cert.subject.CN || JSON.stringify(cert.subject), det.is_self_signed ? 'warn' : '']);
    rows.push(['颁发者', cert.issuer?.CN || JSON.stringify(cert.issuer), det.is_self_signed ? 'warn' : '']);
    rows.push(['有效期', (cert.valid_from ? new Date(cert.valid_from * 1000).toLocaleDateString() : '?') + ' → ' + (cert.valid_to ? new Date(cert.valid_to * 1000).toLocaleDateString() : '?'), det.is_expired ? 'bad' : (days < 30 ? 'warn' : 'good')]);
    rows.push(['剩余天数', days + ' 天', det.is_expired ? 'bad' : (days < 30 ? 'warn' : 'good')]);
    rows.push(['是否自签名', det.is_self_signed ? '⚠️ 是' : '✅ 否', det.is_self_signed ? 'bad' : 'good']);
    rows.push(['SAN (域名列表)', cert.san || '无', '']);
  } else {
    rows.push(['证书', '❌ ' + (s.cert_error || '无法获取'), 'bad']);
  }

  // crt.sh
  const crt = s.cert_transparency || {};
  rows.push(['crt.sh 历史证书', crt.found ? '✅ 找到 ' + crt.cert_count + ' 条记录' : '❌ 无公开记录', crt.found ? 'good' : 'bad']);

  let html = kvHtml(rows);

  if (crt.sample_domains && crt.sample_domains.length) {
    html += '<details class="collapsible"><summary>📋 crt.sh 关联子域名</summary><div class="section-grid" style="margin-top:10px">';
    crt.sample_domains.forEach(d => { html += '<div class="kv"><span class="k">' + d + '</span><span class="v">已签发证书</span></div>'; });
    html += '</div></details>';
  }

  document.getElementById('sslSection').innerHTML = html;
}

function renderIp(ip) {
  if (!ip.ips || !Object.keys(ip.ips).length) {
    document.getElementById('ipSection').innerHTML = '<div style="color:#888">无 IP 信息</div>';
    return;
  }
  let html = '';
  Object.entries(ip.ips).forEach(([addr, info]) => {
    html += '<div style="margin-bottom:12px;padding-bottom:12px;border-bottom:1px solid #f1f5f9">';
    html += '<div style="font-weight:700;font-size:1rem;margin-bottom:8px">📡 ' + addr + '</div>';
    html += kvHtml([
      ['国家/地区', [info.country, info.regionName, info.city].filter(Boolean).join(' / ') || '未知', ''],
      ['ISP', info.isp || info.org || '未知', ''],
      ['AS', info.as || '未知', ''],
      ['定位', info.loc || '未知', ''],
    ]);
    if (info.hosting_flags && info.hosting_flags.length) {
      html += '<div style="margin-top:8px">';
      info.hosting_flags.forEach(f => {
        html += '<span class="tag warning">' + f + '</span> ';
      });
      html += '</div>';
    }
    html += '</div>';
  });
  document.getElementById('ipSection').innerHTML = html;
}

function renderContent(c) {
  if (!c.has_body) {
    document.getElementById('contentSection').innerHTML = '<div style="color:#888;padding:10px">⚠️ ' + (c.issues[0] || '无法获取页面内容') + '</div>';
    return;
  }

  let html = '';
  html += kvHtml([
    ['HTML Title', c.html_title || '(空)', ''],
    ['页面大小', c.content_size + ' bytes', ''],
    ['Content-Type', c.content_type || '未知', ''],
    ['Script 数量', c.script_count, c.script_count > 20 ? 'warn' : ''],
    ['外链数量', c.external_urls.length, c.external_urls.length > 10 ? 'warn' : ''],
    ['重定向行为', c.redirects.length ? '⚠️ ' + c.redirects.length + ' 处' : '✅ 无', c.redirects.length ? 'bad' : 'good'],
    ['可疑模式匹配', Object.keys(c.pattern_matches || {}).length ? '⚠️ ' + JSON.stringify(c.pattern_matches) : '✅ 无', Object.keys(c.pattern_matches || {}).length ? 'bad' : 'good'],
    ['钓鱼话术', c.phishing_keywords.length ? '⚠️ ' + c.phishing_keywords.join(' / ') : '✅ 无', c.phishing_keywords.length ? 'bad' : 'good'],
  ]);

  // 表单
  if (c.forms && c.forms.length) {
    html += '<div style="margin-top:14px"><div style="font-weight:600;margin-bottom:8px">📝 检测到 ' + c.forms.length + ' 个表单</div>';
    c.forms.forEach(f => {
      html += '<div class="form-card">';
      html += '<div class="form-action ' + (f.action && !f.action.startsWith('/') && !f.action.startsWith('#') ? 'bad' : '') + '">action: ' + (f.action || '当前页面') + ' · method: ' + f.method + '</div>';
      html += '<div class="form-inputs">';
      (f.inputs || []).forEach(inp => {
        const cls = inp.type === 'password' ? 'password' : '';
        html += '<span class="inp ' + cls + '">' + (inp.type || 'text') + (inp.name ? ' · ' + inp.name : '') + '</span>';
      });
      html += '</div>';
      if (f.has_password) html += '<div style="margin-top:6px;color:#dc2626;font-size:0.8rem">⚠️ 包含密码输入字段</div>';
      html += '</div>';
    });
    html += '</div>';
  }

  document.getElementById('contentSection').innerHTML = html;
}

function renderHeaders(h) {
  if (!h || !Object.keys(h).length) {
    document.getElementById('headersSection').innerHTML = '<div style="color:#888">无安全头数据</div>';
    return;
  }
  let html = '';
  Object.values(h).forEach(header => {
    html += '<div class="header-check">';
    html += '<div><div class="header-name">' + header.name + '</div><div class="header-desc">' + header.desc + '</div></div>';
    html += '<span class="header-status ' + (header.present ? 'present' : 'missing') + '">' + (header.present ? '✅ 已设置' : '❌ 缺失') + '</span>';
    html += '</div>';
  });
  document.getElementById('headersSection').innerHTML = html;
}

function kvHtml(rows) {
  let h = '';
  rows.forEach(([k, v, cls]) => {
    h += '<div class="kv"><span class="k">' + k + '</span><span class="v ' + (cls || '') + '">' + v + '</span></div>';
  });
  return h;
}

// Enter key 触发
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') startCheck();
});

// 默认载入一个 URL 展示
window.addEventListener('load', () => {
  const params = new URLSearchParams(window.location.search);
  const preset = params.get('url');
  if (preset) {
    document.getElementById('urlInput').value = preset;
    startCheck();
  }
});
</script>
</body>
</html>
