# demo-nodejs-server — tích hợp CShield Node.js SDK (ES256)

Server Express mẫu tích hợp `nodejs-c-shield-sdk` (bản thuần **ES256**): verify chữ ký thiết bị
trên request đến + ký RSA cho response trả về.

> **SDK**: `nodejs-c-shield-sdk@2.0.0` (vendored tại `vendor/`) · **Node.js 18+** · **Express 5**
> API & chi tiết đầy đủ xem `README.md` của SDK trong gói.

---

## 1. Mô hình

```
Request:   App ──[cs-proof: accessToken ES256 + chữ ký thiết bị]──▶  Server (verify OFFLINE qua JWKS)
Response:  App ◀──[cs-timestamp, cs-signature]───────────────────── Server (ký RSA private key)
```

- **Verify request** dùng chữ ký THIẾT BỊ (ECDSA P-256, hardware-backed). Public key thiết bị +
  `trustLevel` rút từ **access token ES256** trong header `cs-proof`, verify OFFLINE qua JWKS của
  realm. SDK chạy **thuần ES256 — không fallback**. Route bảo vệ bắt buộc có `cs-proof`, thiếu là
  `400 CSHIELD_MISSING_SIGNATURE_HEADER`.
- **Ký response** bằng RSA-SHA256 với private key server (chỗ DUY NHẤT cần cấu hình khóa).

## 2. Cài đặt & chạy

```bash
npm install          # cài từ vendor/nodejs-c-shield-sdk-2.0.0.tgz
cp .env.example .env # điền CSHIELD_PRIVATE_KEY (base64 PEM)
npm start            # http://0.0.0.0:8080
```

## 3. Biến môi trường

| Biến | Bắt buộc | Mô tả |
|------|:---:|-------|
| `CSHIELD_PRIVATE_KEY` | ✅ | Private key RSA **ký response**, base64-encoded PEM (`base64 -w 0 private.pem`) |
| `CSHIELD_CUSTOMER_CODE` | — | Mã khách (mặc định `CMCCS`) — truyền nguyên như license |
| `CSHIELD_APPLICATION_ID` | — | Định danh app (mặc định `cshield-embedded-sample`) — truyền nguyên như license |
| `CSHIELD_JWKS_BASE_URL` | — | Gốc URL JWKS (BE phát hành token DEV). Bỏ trống → URL bake sẵn trong gói SDK |
| `CSHIELD_MIN_TRUST_LEVEL` | — | Ngưỡng trust tối thiểu `L1..L5` (mặc định `L1`) |
| `PORT` | — | Cổng (mặc định `8080`) |

> **`environment` cố định `DEV` trong code** (`CShieldEnvironment.DEV`). Realm hiệu dụng =
> `cmccs:cshield-embedded-sample:dev`, `aud` kỳ vọng = `tenant:cmccs:cshield-embedded-sample:dev`.
> Cả 3 trường realm do SERVER tự pin, KHÔNG lấy từ token client — đây là điều kiện để chặn token
> cross-app / cross-env.

## 4. Routes

| Method | Path | Bảo vệ | Mô tả |
|--------|------|:---:|-------|
| GET | `/test` | — | Healthcheck, trả `{ success, message }` |
| POST | `/verify-otp` | ✅ | Verify request + ký response. Body `{ "otp": "123456" }` |

## 5. Cấu hình (src/server.js)

```js
const requestVerifier = new DefaultRequestVerifier({
  realm: {
    customerCode: "CMCCS",                    // từ license
    applicationId: "cshield-embedded-sample", // từ license
    environment: CShieldEnvironment.DEV,
  },
});

const shield = new CShield({
  requestVerifier,
  responseSigner: new DefaultResponseSigner(new DefaultPrivateKeyProvider(privateKey)),
  requestTimeoutSeconds: 60,          // cửa sổ chống replay cho cs-proof
  // minTrustLevel: "L2",             // chốt chặn thiết bị yếu/giả lập
});

app.post("/verify-otp", ...shield.middlewares(), handler);
app.use(shield.errorHandler());       // đặt sau cùng
```

Body parser phải kèm `captureRawBody` (SDK hash RAW bytes của body):
```js
app.use(express.json({ verify: captureRawBody }));
```

## 6. Exception → HTTP (verify request)

| Code | HTTP | Khi nào |
|------|:---:|--------|
| `CSHIELD_MISSING_SIGNATURE_HEADER` | 400 | Thiếu header `cs-proof` |
| `CSHIELD_INVALID_PROOF` | 400 | `cs-proof` sai base64/JSON/thiếu field |
| `CSHIELD_STALE_REQUEST` | 401 | `timestamp` ngoài cửa sổ tươi |
| `CSHIELD_REPLAY_DETECTED` | 401 | `requestId` đã dùng |
| `CSHIELD_SIGNATURE_MISMATCH` | 401 | Chữ ký thiết bị không khớp canonical request |
| `CSHIELD_INVALID_ACCESS_TOKEN` | 401 | Token sai/hết hạn/sai `aud`/sai chữ ký/không phải ES256 |
| `CSHIELD_DEVICE_NOT_ALLOWED` | 403 | `trustLevel` dưới ngưỡng |
| `CSHIELD_DEVICE_KEY_UNAVAILABLE` | 502 | Không tải được JWKS của realm |
