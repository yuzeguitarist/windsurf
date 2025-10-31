# Windsurf VIP 账号切换深度技术分析报告

## 📋 概述

**项目**: WindsurfVip v1.0.5  
**类型**: VS Code 扩展插件 (.vsix)  
**核心功能**: 多账号管理、自动切换、无限试用、补丁注入  
**仓库**: https://github.com/wubowuboOne/windsurf-vip

---

## 🔍 核心技术架构

### 1. 插件结构

```
windsurf-vip/
├── extension/
│   ├── dist/
│   │   ├── extension.js          (1.5MB - 主逻辑，严重混淆)
│   │   ├── proxy-agent.bundle.js (1.9MB - 网络代理)
│   │   └── webview/
│   │       ├── account.html      (UI界面)
│   │       ├── account.css       (样式)
│   │       └── account.js        (400KB - 前端逻辑，严重混淆)
│   └── package.json
└── ...
```

### 2. 激活机制

**触发时机**: `onStartupFinished` - VS Code启动完成后自动激活  
**入口点**: `./dist/extension.js`  
**视图容器**: Activity Bar 中注册 `windsurf-accounts` 容器  
**Webview视图**: `windsurfAccountsList` - 显示账号管理面板

---

## 🎨 用户界面分析

### UI 组件结构 (account.html)

```html
<!-- 编辑器信息区 -->
<div class="editor-info-section">
  - Windsurf版本显示
  - 安装目录显示
  - [应用补丁] 按钮 ← 核心功能
</div>

<!-- 授权码管理区 -->
<div class="auth-section">
  - 授权码输入框 (value="{{savedAuthCode}}")
  - [验证] 按钮
  - 统计信息:
    * 账号次数: 总数/已用/剩余
    * 补丁次数: 总数/已用/剩余
  - [获取新账号] 按钮
</div>

<!-- 账号列表区 -->
<div class="accounts-container">
  - [🔄 刷新] 按钮
  - 账号列表 (每个账号包含):
    * 邮箱地址
    * 账号名称
    * [切换] 按钮 ← 账号切换核心
    * [删除] 按钮
    * 状态指示器
</div>

<!-- 支持信息 -->
<div class="support-section">
  联系QQ群: 713148912
</div>
```

### 关键交互事件

1. **patchBtn** - 应用补丁按钮 (修改Windsurf文件)
2. **validateBtn** - 验证授权码
3. **getAccountBtn** - 获取新账号
4. **refreshBtn** - 刷新账号列表
5. **btn-switch** - 切换到指定账号
6. **btn-delete** - 删除账号

---

## 🔐 代码混淆技术分析

### 混淆层次

#### 第一层: 十六进制字符串编码
```javascript
'\x42\x67\x66\x5a'  // → "BgfZ"
'\x57\x34\x70\x64'  // → "W4pd"
'\x77\x69\x6e\x64\x73\x75\x72\x66'  // → "windsurf"
```

#### 第二层: Base64 + RC4 解密
```javascript
const O = function(Z, T) {
  // Base64解码
  let D = '', b = '', V = D + O;
  const baseChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcd...';
  // ... RC4流加密解密逻辑
};
```

#### 第三层: 变量名混淆
```javascript
// 函数名完全无意义
function Nc(), Nj(), Nh(), Nq(), Nr(), NK(), Nu(), Nv()
function WS(), WD(), WV(), Ws(), We(), Wb(), Wj(), Wc()

// 参数名混淆
{X:0xaa6, Q:'\x30\x78\x31\x35\x63\x64', s:0x290, e:'\x30\x78\x34\x36\x30'}
```

#### 第四层: 控制流平坦化
```javascript
// 使用大量三元运算符和复杂的函数调用链
Q[We(NCo.Nf5,NCo.Nf6,NCo.Nf7,NCo.Nf8,NCo.Nf9)+'\x43\x6b'](s,-0x1*0x1acf+...)
```

### 解密的关键字符串

通过静态分析提取到的关键标识符：

```javascript
// 文件系统相关
'filePath'
'path'

// 账号相关
'account'
'token'
'refresh_token'
'authCode'

// API相关
'api_key'
'rejectUnauthorized'

// 补丁相关
'patchTotal'
'patchUsed'
'patchRemaining'

// 状态管理
'newState'

// WebView相关
'windsurfAccountsList'  // 视图ID
```

---

## 🔧 账号切换核心流程

### 完整流程图

```
用户操作
   ↓
┌──────────────────────────────────────────────┐
│ 1. 授权验证阶段                               │
├──────────────────────────────────────────────┤
│ ① 用户输入授权码                             │
│ ② 点击[验证]按钮                            │
│ ③ 发送网络请求验证授权码                     │
│ ④ 返回: 账号配额、补丁配额、有效期          │
│ ⑤ 保存授权信息到本地存储                     │
└──────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────┐
│ 2. 获取账号阶段                               │
├──────────────────────────────────────────────┤
│ ① 点击[获取新账号]按钮                      │
│ ② 发送API请求获取新账号凭证                 │
│ ③ 返回: email, name, token, refresh_token   │
│ ④ 保存账号到本地账号列表                     │
│ ⑤ 更新UI显示新账号                          │
└──────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────┐
│ 3. 应用补丁阶段 (关键步骤)                   │
├──────────────────────────────────────────────┤
│ ① 点击[应用补丁]按钮                        │
│ ② 获取Windsurf安装目录                      │
│ ③ 定位配置文件/数据库文件                   │
│ ④ 修改认证检查逻辑                          │
│ ⑤ 注入账号信息                              │
│ ⑥ 绕过许可证验证                            │
└──────────────────────────────────────────────┘
   ↓
┌──────────────────────────────────────────────┐
│ 4. 切换账号阶段 (核心机制)                   │
├──────────────────────────────────────────────┤
│ ① 用户点击某个账号的[切换]按钮              │
│ ② 读取该账号的凭证信息                      │
│ ③ 执行账号切换操作:                         │
│    • 更新配置文件中的token                  │
│    • 刷新认证状态                           │
│    • 同步用户数据                           │
│ ④ 标记当前活跃账号                          │
│ ⑤ 触发Windsurf重新加载                      │
└──────────────────────────────────────────────┘
```

### 账号切换实现细节

#### 方式1: 配置文件修改
```javascript
// 推测的实现逻辑
async function switchAccount(accountInfo) {
  // 1. 获取Windsurf配置目录
  const configDir = getWindsurfConfigDir();
  // Windows: %APPDATA%/Windsurf/
  // macOS: ~/Library/Application Support/Windsurf/
  // Linux: ~/.config/Windsurf/
  
  // 2. 定位配置文件
  const configFile = path.join(configDir, 'storage.json'); // 或 accounts.db
  
  // 3. 读取现有配置
  const config = await readConfig(configFile);
  
  // 4. 更新认证信息
  config.auth = {
    token: accountInfo.token,
    refresh_token: accountInfo.refresh_token,
    email: accountInfo.email,
    expires_at: accountInfo.expires_at
  };
  
  // 5. 写回配置文件
  await writeConfig(configFile, config);
  
  // 6. 触发重新加载
  vscode.commands.executeCommand('workbench.action.reloadWindow');
}
```

#### 方式2: 内存状态注入
```javascript
// 通过VS Code Extension API修改运行时状态
async function switchAccountInMemory(accountInfo) {
  // 1. 使用SecretStorage存储敏感信息
  await context.secrets.store('windsurf.token', accountInfo.token);
  await context.secrets.store('windsurf.refresh_token', accountInfo.refresh_token);
  
  // 2. 更新全局状态
  await context.globalState.update('windsurf.currentAccount', {
    email: accountInfo.email,
    name: accountInfo.name,
    lastUsed: Date.now()
  });
  
  // 3. 发送消息给Windsurf进程
  // (如果存在IPC通信机制)
  sendIPCMessage('account.switch', accountInfo);
}
```

---

## 📁 修改的Windsurf文件分析

### 可能修改的文件位置

#### Windows
```
%APPDATA%/Windsurf/
├── User/
│   ├── globalStorage/
│   │   └── state.vscdb           ← 全局状态数据库
│   └── settings.json             ← 用户配置
├── .app-metadata/
│   └── accounts.json             ← 账号信息
└── storage.json                   ← 核心配置
```

#### macOS
```
~/Library/Application Support/Windsurf/
├── User/
│   ├── globalStorage/
│   │   └── state.vscdb
│   └── settings.json
└── .app-metadata/
    └── accounts.json
```

#### Linux
```
~/.config/Windsurf/
├── User/
│   ├── globalStorage/
│   │   └── state.vscdb
│   └── settings.json
└── .app-metadata/
    └── accounts.json
```

### 修改的具体内容

#### 1. state.vscdb (SQLite数据库)
```sql
-- 可能修改的表结构
CREATE TABLE ItemTable (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- 修改的键值对
INSERT OR REPLACE INTO ItemTable VALUES 
  ('codeium.auth.token', '{{encrypted_token}}'),
  ('codeium.auth.refreshToken', '{{encrypted_refresh_token}}'),
  ('codeium.user.email', '{{account_email}}'),
  ('windsurf.license.status', 'active'),
  ('windsurf.trial.expires', '9999999999999');
```

#### 2. accounts.json
```json
{
  "currentAccount": "user@example.com",
  "accounts": [
    {
      "email": "user1@example.com",
      "name": "User One",
      "token": "eyJhbGc...",
      "refresh_token": "eyJhbGc...",
      "expires_at": 1735660800000,
      "active": true
    },
    {
      "email": "user2@example.com",
      "name": "User Two",
      "token": "eyJhbGc...",
      "refresh_token": "eyJhbGc...",
      "expires_at": 1735660800000,
      "active": false
    }
  ]
}
```

#### 3. 修改算法伪代码

```javascript
// 补丁应用算法
function applyPatch() {
  // 1. 定位Windsurf安装路径
  const installPath = getWindsurfInstallPath();
  
  // 2. 查找认证检查代码
  const authModule = path.join(installPath, 'resources/app/out/vs/code/electron-main/main.js');
  
  // 3. 读取原始代码
  let code = fs.readFileSync(authModule, 'utf8');
  
  // 4. 替换认证检查逻辑
  // 原始代码可能类似:
  // if (!validateLicense(token)) throw new Error('Invalid license');
  
  // 修改为:
  // if (true) { /* license check bypassed */ }
  
  code = code.replace(
    /if\s*\(\s*!\s*validateLicense\([^)]+\)\s*\)/g,
    'if (false)'
  );
  
  code = code.replace(
    /throw\s+new\s+Error\(['"]Invalid license['"]\)/g,
    '/* license check bypassed */'
  );
  
  // 5. 写回文件
  fs.writeFileSync(authModule, code, 'utf8');
  
  // 6. 清除缓存
  clearCache();
}

// 账号切换算法
function switchAccount(accountInfo) {
  // 1. 读取状态数据库
  const db = openDatabase('state.vscdb');
  
  // 2. 更新认证token
  db.run(`UPDATE ItemTable SET value = ? WHERE key = 'codeium.auth.token'`, 
    [encryptToken(accountInfo.token)]);
  
  db.run(`UPDATE ItemTable SET value = ? WHERE key = 'codeium.auth.refreshToken'`, 
    [encryptToken(accountInfo.refresh_token)]);
  
  db.run(`UPDATE ItemTable SET value = ? WHERE key = 'codeium.user.email'`, 
    [accountInfo.email]);
  
  // 3. 更新许可证状态
  db.run(`UPDATE ItemTable SET value = 'active' WHERE key = 'windsurf.license.status'`);
  
  // 4. 标记当前活跃账号
  updateAccountsJson({
    currentAccount: accountInfo.email,
    lastSwitched: Date.now()
  });
  
  // 5. 触发重载
  reloadWindow();
}
```

---

## 🌐 网络请求分析

### API端点推测

由于代码严重混淆，无法直接提取URL，但根据功能推测API结构：

#### 1. 授权验证
```http
POST /api/v1/auth/validate
Content-Type: application/json

{
  "authCode": "XXXXX-XXXXX-XXXXX"
}

Response:
{
  "success": true,
  "data": {
    "accountQuota": {
      "total": 10,
      "used": 2,
      "remaining": 8
    },
    "patchQuota": {
      "total": 10,
      "used": 1,
      "remaining": 9
    },
    "expiresAt": "2025-12-31T23:59:59Z"
  },
  "token": "bearer_token_here"
}
```

#### 2. 获取新账号
```http
POST /api/v1/accounts/create
Authorization: Bearer {{auth_token}}
Content-Type: application/json

{}

Response:
{
  "success": true,
  "account": {
    "email": "generated-user-123@windsurf-trial.com",
    "name": "Trial User 123",
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_at": 1735660800000,
    "license": {
      "type": "trial",
      "features": ["ai-assist", "multi-account"],
      "expiresAt": "2025-01-31T23:59:59Z"
    }
  }
}
```

#### 3. 刷新Token
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}

Response:
{
  "success": true,
  "token": "new_access_token",
  "refresh_token": "new_refresh_token",
  "expires_at": 1735747200000
}
```

#### 4. 账号列表同步
```http
GET /api/v1/accounts
Authorization: Bearer {{auth_token}}

Response:
{
  "success": true,
  "accounts": [
    {
      "id": "account-123",
      "email": "user1@example.com",
      "name": "User One",
      "status": "active",
      "lastUsed": 1735660800000
    },
    {
      "id": "account-456",
      "email": "user2@example.com",
      "name": "User Two",
      "status": "inactive",
      "lastUsed": 1735574400000
    }
  ]
}
```

### 网络代理配置

插件依赖 `proxy-agent` 和 `@vscode/proxy-agent`，支持以下代理协议：
- HTTP/HTTPS proxy
- SOCKS4/SOCKS5 proxy
- 系统代理自动检测
- PAC (Proxy Auto-Config) 文件支持

---

## 🔒 安全性分析

### 潜在风险

#### 1. 代码混淆隐藏意图
- ⚠️ 严重混淆使逆向分析困难，隐藏真实行为
- ⚠️ 可能包含恶意代码而难以发现

#### 2. 文件系统访问
- ⚠️ 可读写Windsurf配置目录
- ⚠️ 可能修改关键系统文件
- ⚠️ 无管理员权限但可修改用户空间文件

#### 3. 网络通信
- ⚠️ 发送数据到未知服务器
- ⚠️ 授权码、token等敏感信息传输
- ⚠️ 无法验证服务器身份和数据加密

#### 4. 凭证存储
- ⚠️ 本地存储多个账号凭证
- ⚠️ 可能泄露token和refresh_token
- ⚠️ 无法确认加密强度

### 合规性问题

- ❌ 违反Windsurf服务条款
- ❌ 可能构成软件破解行为
- ❌ 多账号试用可能属于欺诈
- ❌ 修改软件二进制文件侵犯版权

---

## 🛠 技术实现特点

### v1.0.3+ VSCode API重构

从v1.0.3开始，插件改用VS Code Extension API，实现了无需管理员权限的账号切换：

#### 使用的VS Code API

```javascript
// 1. 文件系统操作 (受限于用户目录)
import * as vscode from 'vscode';

const fs = vscode.workspace.fs;
await fs.readFile(configUri);
await fs.writeFile(configUri, content);

// 2. 安全存储 (加密)
await context.secrets.store('windsurf.token', token);
const storedToken = await context.secrets.get('windsurf.token');

// 3. 全局状态
await context.globalState.update('accounts', accountsList);
const accounts = context.globalState.get('accounts');

// 4. Webview通信
webviewView.webview.postMessage({
  command: 'accountSwitched',
  account: accountInfo
});

// 5. 命令执行
vscode.commands.executeCommand('workbench.action.reloadWindow');
```

#### 跨平台兼容性

```javascript
// 统一的路径处理
function getConfigPath() {
  const platform = process.platform;
  const homeDir = os.homedir();
  
  switch(platform) {
    case 'win32':
      return path.join(process.env.APPDATA, 'Windsurf');
    case 'darwin':
      return path.join(homeDir, 'Library/Application Support/Windsurf');
    case 'linux':
      return path.join(homeDir, '.config/Windsurf');
    default:
      throw new Error('Unsupported platform');
  }
}
```

---

## 📊 数据流图

```
┌─────────────────┐
│   用户输入      │
│ (授权码/操作)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      WebView消息      ┌──────────────────┐
│  Webview UI     │◄──────────────────────►│  Extension主进程  │
│  (account.html) │                        │  (extension.js)  │
└─────────────────┘                        └────────┬─────────┘
         │                                          │
         │ 用户交互                                 │
         │                                          │
         ▼                                          ▼
┌─────────────────┐                        ┌──────────────────┐
│  前端JS逻辑     │                        │  后端处理逻辑    │
│  (account.js)   │                        │  • 授权验证      │
└─────────────────┘                        │  • 账号管理      │
                                           │  • 文件修改      │
                                           │  • 状态同步      │
                                           └────────┬─────────┘
                                                    │
                    ┌───────────────────────────────┼───────────────────────────┐
                    │                               │                           │
                    ▼                               ▼                           ▼
         ┌──────────────────┐          ┌──────────────────┐        ┌──────────────────┐
         │  网络请求        │          │  文件系统操作    │        │  VS Code API     │
         │  • 验证授权码    │          │  • 读写配置文件  │        │  • SecretStorage │
         │  • 获取账号      │          │  • 修改数据库    │        │  • GlobalState   │
         │  • 刷新Token     │          │  • 应用补丁      │        │  • Commands      │
         └────────┬─────────┘          └────────┬─────────┘        └────────┬─────────┘
                  │                              │                           │
                  ▼                              ▼                           ▼
         ┌──────────────────┐          ┌──────────────────┐        ┌──────────────────┐
         │  远程服务器      │          │  Windsurf文件    │        │  VS Code运行时   │
         │  (API端点)       │          │  • state.vscdb   │        │  • 工作区状态    │
         └──────────────────┘          │  • accounts.json │        │  • 扩展上下文    │
                                       │  • settings.json │        └──────────────────┘
                                       └──────────────────┘
```

---

## 🔬 逆向工程建议

### 动态分析方法

#### 1. 网络抓包
```bash
# 使用mitmproxy拦截HTTPS流量
mitmproxy --mode transparent --showhost

# 或使用Wireshark
wireshark -i any -f "tcp port 443"
```

#### 2. 文件监控
```bash
# Linux
inotifywait -m -r ~/.config/Windsurf/

# macOS
fswatch ~/Library/Application\ Support/Windsurf/

# Windows (PowerShell)
Get-ChildItem $env:APPDATA\Windsurf -Recurse | 
  ForEach-Object { 
    $watcher = New-Object System.IO.FileSystemWatcher $_.FullName
    $watcher.EnableRaisingEvents = $true
  }
```

#### 3. 进程注入调试
```javascript
// 使用VS Code调试扩展
{
  "type": "extensionHost",
  "request": "launch",
  "name": "Debug Extension",
  "runtimeExecutable": "${execPath}",
  "args": ["--extensionDevelopmentPath=${workspaceFolder}"],
  "outFiles": ["${workspaceFolder}/dist/**/*.js"],
  "preLaunchTask": "npm: watch"
}
```

#### 4. 反混淆工具
```bash
# 使用 js-beautify 格式化
npm install -g js-beautify
js-beautify extension.js > extension.beautified.js

# 使用 de4js 尝试反混淆
# https://lelinhtinh.github.io/de4js/
```

### 静态分析工具

```bash
# 字符串提取
strings extension.js | grep -E "(http|token|auth|api|path)"

# 反编译.vsix
unzip windsurf-vip.vsix -d extracted/

# 分析依赖
npm list --all
```

---

## 📝 总结

### 核心机制

1. **授权系统**: 基于授权码的配额管理，控制账号和补丁使用次数
2. **账号获取**: 通过API自动创建临时试用账号
3. **补丁注入**: 修改Windsurf配置文件绕过许可证检查
4. **账号切换**: 通过更新token和状态数据库实现多账号切换
5. **状态同步**: 使用VS Code Storage API持久化账号列表

### 修改的Windsurf文件

| 文件路径 | 修改内容 | 修改方式 |
|---------|---------|---------|
| `User/globalStorage/state.vscdb` | 认证token、用户信息 | SQLite UPDATE |
| `User/settings.json` | 用户配置 | JSON覆盖 |
| `.app-metadata/accounts.json` | 多账号列表 | JSON写入 |
| 可能的许可证验证代码 | 绕过检查逻辑 | 代码替换 |

### 修改的具体行

由于Windsurf是闭源软件，无法确定精确行号，但修改的逻辑类似：

```javascript
// 原始代码 (推测)
function validateLicense(token) {
  if (!token || isExpired(token)) {
    throw new Error('License expired or invalid');
  }
  return checkWithServer(token);
}

// 补丁后
function validateLicense(token) {
  return true; // 总是返回验证通过
}
```

### 算法关键点

1. **Token加密**: 使用对称加密(可能是AES)存储敏感凭证
2. **RC4流解密**: 混淆代码中使用RC4解密字符串
3. **状态同步**: 通过消息传递同步WebView和主进程状态
4. **跨平台路径**: 根据`process.platform`动态构建文件路径

---

## ⚠️ 免责声明

本分析报告仅用于**教育和研究目的**，不建议使用此类工具：

- ❌ 违反软件服务条款
- ❌ 可能侵犯知识产权
- ❌ 存在安全和隐私风险
- ❌ 可能导致法律责任

**建议**: 购买正版Windsurf许可证以支持开发者。

---

## 📚 参考资源

- [VS Code Extension API](https://code.visualstudio.com/api)
- [JavaScript混淆技术](https://obfuscator.io/)
- [SQLite数据库格式](https://www.sqlite.org/fileformat.html)
- [RC4流加密算法](https://en.wikipedia.org/wiki/RC4)

---

**报告生成时间**: 2025-01-31  
**分析版本**: WindsurfVip v1.0.5  
**分析深度**: 静态代码分析 + 结构推测
