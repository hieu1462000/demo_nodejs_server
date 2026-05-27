# CShield Node.js SDK — Hướng dẫn sử dụng

> **Version**: `cshield-sdk@1.0.0`  
> **Peer dependency**: `express >= 4.0.0`  
> **Yêu cầu**: Node.js 18+

---

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Cài đặt](#2-cài-đặt)
3. [Biến môi trường](#3-biến-môi-trường)
4. [Khởi tạo SDK — `CShield.create()`](#4-khởi-tạo-sdk--cshieldcreate)
5. [Cấu hình License — `LicenseConfig`](#5-cấu-hình-license--licenseconfig)
6. [Middleware](#6-middleware)
   - [verifyMiddleware](#61-verifymiddleware)
   - [signMiddleware](#62-signmiddleware)
   - [errorHandler](#63-errorhandler)
7. [Request Verifier](#7-request-verifier)
8. [Response Signer](#8-response-signer)
9. [License Status & Lifecycle](#9-license-status--lifecycle)
10. [Graceful Shutdown](#10-graceful-shutdown)
11. [Xử lý ngoại lệ](#11-xử-lý-ngoại-lệ)
12. [Ví dụ đầy đủ](#12-ví-dụ-đầy-đủ)
13. [Luồng hoạt động nội bộ](#13-luồng-hoạt-động-nội-bộ)

---

## 1. Tổng quan kiến trúc

CShield SDK là một lớp bảo mật cho server Node.js/Express, được thiết kế theo mô hình **"Rust decides, JS only reads"**.

## 2. Cài đặt

```bash
# Cài từ tarball (local)
npm install file:./cshield-sdk-*.tgz

# Cài express (peer dependency)
npm install express
```

Import trong code:

```js
// CommonJS
const { CShield, DefaultRequestVerifier, DefaultResponseSigner, DefaultPrivateKeyProvider } = require('cshield-sdk');

// ESM / TypeScript
import { CShield, DefaultRequestVerifier, DefaultResponseSigner, DefaultPrivateKeyProvider } from 'cshield-sdk';
```

---

## 3. Biến môi trường

| Biến | Mô tả | Bắt buộc |
|------|--------|----------|
| `CSHIELD_LICENSE_KEY` | Raw JWT string của license | ✅ |
| `CSHIELD_PRIVATE_KEY` | Private key RSA dạng **base64-encoded PEM** | ✅ |

**Encode private key sang base64:**
```bash
base64 -w 0 path/to/private.pem
# Hoặc trên macOS:
base64 -i path/to/private.pem | tr -d '\n'
```

File `.env` mẫu:
```env
CSHIELD_PRIVATE_KEY='LS0tLS1CRUdJTiBQUklWQVRF...'
CSHIELD_LICENSE_KEY='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
```

---

## 4. Khởi tạo SDK — `CShield.create()`

`CShield.create()` là **factory method bất đồng bộ** — phải `await` và phải được gọi **trước khi** đăng ký routes bảo mật.

```js
const cshield = await CShield.create({
  license: {
    licenseKey: process.env.CSHIELD_LICENSE_KEY,
    gracePath: './.cshield.grace',
    appId: {
      ios: 'com.example.MyApp',
      android: 'com.example.my_app',
    },
    onStatusChange: (status) => {
      console.log(`[CShield] License status: ${status}`);
    },
    onRenew: async (newToken) => {
      // Lưu token mới vào DB hoặc file config
      await saveTokenToDatabase(newToken);
    },
  },
});
```

> **Nếu license không hợp lệ**, `CShield.create()` sẽ throw exception.

---

## 5. Cấu hình License — `LicenseConfig`

```typescript
interface LicenseConfig {
  licenseKey: string;           // ★ BẮT BUỘC — JWT license string
  gracePath?: string;           // Đường dẫn file grace (mặc định: ./.cshield.grace)
  appId: {                      // ★ BẮT BUỘC — bundle ID của app
    ios: string;                // e.g. "com.example.MyApp"
    android: string;            // e.g. "com.example.my_app"
  };
  onStatusChange?: (status: LicenseStatus) => void;  // Callback khi trạng thái thay đổi
  onRenew: (newToken: string) => Promise<void>;       // ★ BẮT BUỘC — xử lý token mới
  maxGraceBoots?: number;       // Số lần restart tối đa trong grace period (mặc định: không giới hạn)
}
```

### Giải thích các trường

| Trường | Mô tả |
|--------|--------|
| `licenseKey` | JWT được cấp bởi CShield license server. |
| `gracePath` | File lưu trạng thái offline grace period. |
| `appId` | Package name, Bundle ID được nhúng trong JWT |
| `onStatusChange` | Gọi khi Rust chuyển trạng thái license: `VALID` → `GRACE_PERIOD` → `EXPIRED` → `REVOKED` |
| `onRenew` | Gọi khi server trả về JWT mới. **Phải lưu token mới** để dùng cho lần khởi động tiếp theo |
| `maxGraceBoots` | Số lần boot tối đa trong grace period. Default: 999999 |

---

## 6. Middleware

### 6.1 `verifyMiddleware`

Middleware xác thực **chữ ký request** từ client SDK.

```js
app.post('/api/endpoint', cshield.verifyMiddleware(requestVerifier), handler);
```

**Luồng xử lý:**
1. Gọi **Rust gate** (`cshield_check_license_status`) — quyết định allow/block
2. Nếu blocked → throw exception phù hợp (`LicenseExpiredException`, v.v.)
3. Nếu đang trong grace period → set header `X-CShield-License: grace-period`
4. Đọc headers `cs-timestamp` và `cs-signature` từ request
5. Hash body bằng SHA-256
6. Xây dựng payload: `METHOD.PATH.TIMESTAMP.BODY_HASH`
7. Gọi **Rust** để verify chữ ký RSA-SHA256

**Required request headers từ client:**

| Header | Giá trị |
|--------|---------|
| `cs-timestamp` | Unix timestamp (giây) khi client gửi request |
| `cs-signature` | Chữ ký RSA-SHA256 của payload |

> ⚠️ Request sẽ bị reject nếu `|now - cs-timestamp| > timeoutSeconds` (mặc định 30 giây).

---

### 6.2 `signMiddleware`

Middleware **ký response** trước khi trả về client.

```js
app.post('/api/endpoint',
  cshield.verifyMiddleware(requestVerifier),
  cshield.signMiddleware(responseSigner),
  handler
);
```

**Luồng xử lý:**
1. Gọi **Rust gate** — quyết định allow/block (giống verifyMiddleware)
2. Override `res.json()` để tự động ký response
3. Khi handler gọi `res.json(body)`:
   - Hash body bằng SHA-256
   - Xây dựng payload: `STATUS.PATH.TIMESTAMP.BODY_HASH`
   - Ký bằng private key (RSA-SHA256)
   - Thêm headers `cs-timestamp` và `cs-signature` vào response

**Response headers được thêm tự động:**

| Header | Giá trị |
|--------|---------|
| `cs-timestamp` | Unix timestamp tại thời điểm ký |
| `cs-signature` | Chữ ký RSA-SHA256 của response payload |

---

### 6.3 `errorHandler`

Error handler toàn cục — **phải đặt SAU TẤT CẢ routes**.

```js
app.use(cshield.errorHandler(new DefaultErrorWriter(responseSigner)));
// Hoặc với custom error writer:
app.use(cshield.errorHandler(customErrorWriter));
```

**HTTP status codes:**

| Exception | HTTP Status | Code |
|-----------|-------------|------|
| `LicenseExpiredException` | `403` | `LICENSE_EXPIRED` |
| `LicenseRevokedException` | `403` | `LICENSE_REVOKED` |
| `InvalidLicenseException` | `403` | `INVALID_LICENSE` |
| `MissingSignatureHeaderException` | `400` | `BAD_REQUEST` |
| `TimeoutRequestException` | `408` | `REQUEST_TIMEOUT` |
| `InvalidSignatureException` | `401` | `UNAUTHORIZED` |
| Lỗi khác | `500` | `INTERNAL_ERROR` |

---

## 7. Request Verifier

```js
const requestVerifier = new DefaultRequestVerifier(/* timeoutSeconds = 30 */);
```

`DefaultRequestVerifier` là implementation mặc định của abstract class `RequestVerifier`. Có thể tùy chỉnh `timeoutSeconds`:

```js
const requestVerifier = new DefaultRequestVerifier(60); // 60 giây timeout
```

**Custom Verifier** (nếu cần override logic):
```typescript
import { RequestVerifier } from 'cshield-sdk';

class MyRequestVerifier extends RequestVerifier {
  constructor() {
    super(45); // custom timeout
  }
}
```

> ⚠️ `_rustVerify` được inject tự động bởi `verifyMiddleware` — không gọi thủ công.

---

## 8. Response Signer

```js
// Bước 1: Decode private key từ base64
const privateKeyPem = Buffer.from(process.env.CSHIELD_PRIVATE_KEY, 'base64').toString('utf8');

// Bước 2: Tạo key provider
const privateKeyProvider = new DefaultPrivateKeyProvider(privateKeyPem);

// Bước 3: Tạo signer
const responseSigner = new DefaultResponseSigner(privateKeyProvider);
```

**Custom Key Provider** (ví dụ đọc từ AWS Secrets Manager):
```typescript
import { PrivateKeyProvider } from 'cshield-sdk';

class AwsKeyProvider implements PrivateKeyProvider {
  load(): string {
    return fetchKeyFromAwsSecretManager(); // Tùy chỉnh
  }
}
```

---

## 9. License Status & Lifecycle

### Các trạng thái license

```typescript
enum LicenseStatus {
  VALID        = "VALID",         // License hợp lệ, server xác nhận
  GRACE_PERIOD = "GRACE_PERIOD",  // Server không liên lạc được, đang trong thời gian ân hạn
  EXPIRED      = "EXPIRED",       // License đã hết hạn hoặc grace period hết
  REVOKED      = "REVOKED",       // License bị thu hồi bởi server
  INVALID      = "INVALID",       // License không hợp lệ (chữ ký sai, format lỗi)
}
```

### Sơ đồ chuyển đổi trạng thái

```
                    ┌─────────┐
       ┌────────────│  VALID  │◄───────────────────────┐
       │            └────┬────┘                        │
       │ Server          │ Server offline          Renewal
       │ revokes         │                             │
       ▼                 ▼                             │
  ┌─────────┐     ┌─────────────┐              ┌──────────────┐
  │ REVOKED │     │ GRACE_PERIOD│──────────────│   (server    │
  └─────────┘     └──────┬──────┘ grace hết    │  reachable)  │
                         │        hoặc max      └──────────────┘
                         │        boots đạt
                         ▼
                   ┌─────────┐
                   │ EXPIRED │
                   └─────────┘
```

### Lấy trạng thái hiện tại

```js
const status = cshield.getLicenseStatus();
console.log(status); // "VALID" | "GRACE_PERIOD" | "EXPIRED" | "REVOKED" | "INVALID"
```

## 10. Graceful Shutdown

```js
process.on('SIGTERM', () => {
  cshield.shutdown();
  process.exit(0);
});

process.on('SIGINT', () => {
  cshield.shutdown();
  process.exit(0);
});
```

`shutdown()` thực hiện:
1. Xóa heartbeat timer (`clearTimeout`)
2. Giải phóng Rust state machine handle (`stateFree`)

---

## 11. Xử lý ngoại lệ

| Exception | Nguyên nhân |
|-----------|-------------|
| `InvalidLicenseException` | JWT không hợp lệ, appId không khớp, hoặc server từ chối |
| `LicenseExpiredException` | License đã hết hạn (`exp` quá khứ) hoặc grace period hết |
| `LicenseRevokedException` | Server thu hồi license (status `REVOKED`) |
| `MissingSignatureHeaderException` | Request thiếu header `cs-timestamp` hoặc `cs-signature` |
| `TimeoutRequestException` | `|now - cs-timestamp| > timeoutSeconds` |
| `InvalidSignatureException` | Chữ ký RSA không khớp với payload |
| `ResponseSignerException` | Lỗi khi ký response |

---

## 12. Ví dụ đầy đủ

```js
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const express = require('express');
const {
  CShield,
  DefaultRequestVerifier,
  DefaultResponseSigner,
  DefaultPrivateKeyProvider,
} = require('cshield-sdk');

const app = express();
app.use(express.json());

// ── Validate env vars ─────────────────────────────────────
if (!process.env.CSHIELD_PRIVATE_KEY) {
  console.error('Missing env: CSHIELD_PRIVATE_KEY');
  process.exit(1);
}
if (!process.env.CSHIELD_LICENSE_KEY) {
  console.error('Missing env: CSHIELD_LICENSE_KEY');
  process.exit(1);
}

// ── Tạo crypto components ─────────────────────────────────
const privateKey = Buffer.from(process.env.CSHIELD_PRIVATE_KEY, 'base64').toString('utf8');
const privateKeyProvider = new DefaultPrivateKeyProvider(privateKey);
const responseSigner     = new DefaultResponseSigner(privateKeyProvider);
const requestVerifier    = new DefaultRequestVerifier(); // timeout 30s

// ── Route không cần bảo vệ ───────────────────────────────
app.get('/health', (req, res) => {
  res.json({ ok: true });
});

// ── Khởi động async ──────────────────────────────────────
async function startServer() {
  let cshield;

  try {
    cshield = await CShield.create({
      license: {
        licenseKey: process.env.CSHIELD_LICENSE_KEY,
        gracePath: './.cshield.grace',
        appId: {
          ios: 'com.example.MyApp',
          android: 'com.example.my_app',
        },
        onStatusChange: (status) => {
          console.log(`[CShield] Status → ${status}`);
        },
        onRenew: async (newToken) => {
          // TODO: Lưu newToken vào DB hoặc config
          console.log('[CShield] License renewed');
        },
      },
    });
  } catch (err) {
    console.error('[CShield] Startup failed:', err.message);
    process.exit(1);
  }

  // ── Route được bảo vệ ────────────────────────────────────
  app.post(
    '/api/secure-action',
    cshield.verifyMiddleware(requestVerifier),  // 1. Verify request signature
    cshield.signMiddleware(responseSigner),     // 2. Sign response
    (req, res, next) => {
      try {
        // Business logic
        res.json({ success: true, data: 'protected result' });
      } catch (err) {
        next(err);
      }
    }
  );

  // ── Error handler — PHẢI ĐẶT CUỐI CÙNG ─────────────────
  app.use(cshield.errorHandler());

  // ── Graceful shutdown ────────────────────────────────────
  const shutdown = (signal) => {
    console.log(`[CShield] ${signal} received, shutting down...`);
    cshield.shutdown();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));

  // ── Start server ─────────────────────────────────────────
  const PORT = process.env.PORT || 8080;
  const HOST = process.env.HOST || '0.0.0.0';

  app.listen(PORT, HOST, () => {
    console.log(`Server running at http://${HOST}:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
```

---