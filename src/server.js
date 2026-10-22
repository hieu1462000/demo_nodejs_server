require("dotenv").config();

const express = require("express");
const {
  CShield,
  DefaultRequestVerifier,
  DefaultResponseSigner,
  DefaultPrivateKeyProvider,
  CShieldEnvironment,
  captureRawBody,
} = require("nodejs-c-shield-sdk");

const app = express();
// verify: captureRawBody BẮT BUỘC — SDK hash RAW BYTES của body trên dây (không phải
// JSON.stringify(req.body) dựng lại). Thiếu dòng này mọi route JSON verify sẽ 500
// CSHIELD_MISCONFIGURED.
app.use(express.json({ verify: captureRawBody }));

/* =====================================================
   1. Private key KÝ RESPONSE (base64-encoded PEM)
   Encode: base64 -w 0 private.pem  (decode tự động tại runtime)

   KHÔNG cần public key: verify REQUEST dùng chữ ký THIẾT BỊ (ECDSA P-256, hardware-backed).
   Public key thiết bị + trustLevel rút từ access token ES256 trong header cs-proof, verify
   OFFLINE qua JWKS của realm (khai ở §2). SDK chạy THUẦN ES256 — không fallback.
===================================================== */
if (!process.env.CSHIELD_PRIVATE_KEY) {
  console.error("Missing env var: CSHIELD_PRIVATE_KEY");
  process.exit(1);
}

const privateKey = Buffer.from(
  process.env.CSHIELD_PRIVATE_KEY,
  "base64",
).toString("utf8");

const privateKeyProvider = new DefaultPrivateKeyProvider(privateKey);

/* =====================================================
   2. Khởi tạo CShield
   realm = định danh CHÍNH server này (customerCode:applicationId:environment) — BẮT BUỘC, server
   tự pin, KHÔNG lấy từ token client. Dùng để verify access token ES256 offline qua JWKS + bắt
   aud == tenant:<realm>. customerCode/applicationId truyền NGUYÊN như trong license (app sample
   embedded: CMCCS / cshield-embedded-sample); environment = DEV. SDK tự hạ chữ thường.

   => realm hiệu dụng: cmccs:cshield-embedded-sample:dev
      aud kỳ vọng:    tenant:cmccs:cshield-embedded-sample:dev
===================================================== */
const requestVerifier = new DefaultRequestVerifier({
  realm: {
    customerCode: process.env.CSHIELD_CUSTOMER_CODE || "CMCCS",
    applicationId: process.env.CSHIELD_APPLICATION_ID || "cshield-embedded-sample",
    environment: CShieldEnvironment.DEV,
  },
  // Tùy chọn: trỏ JWKS sang BE đã phát hành token dev (mặc định = URL cloud bake lúc build gói SDK).
  ...(process.env.CSHIELD_JWKS_BASE_URL ? { jwksBaseUrl: process.env.CSHIELD_JWKS_BASE_URL } : {}),
});

const responseSigner = new DefaultResponseSigner(privateKeyProvider);

const shield = new CShield({
  requestVerifier,
  responseSigner,
  // Cửa sổ chống replay (giây) cho timestamp trong cs-proof. Mặc định 30 nếu bỏ qua.
  requestTimeoutSeconds: 60,
  // Ngưỡng trustLevel tối thiểu của thiết bị (L1..L5, mặc định "L1"). Thiết bị dưới ngưỡng ->
  // 403 CSHIELD_DEVICE_NOT_ALLOWED. Chỉnh theo route qua shield.middlewares({ minTrustLevel }).
  ...(process.env.CSHIELD_MIN_TRUST_LEVEL ? { minTrustLevel: process.env.CSHIELD_MIN_TRUST_LEVEL } : {}),
});

/* =====================================================
   3. API không cần verify / sign
===================================================== */
app.get("/test", (req, res) => {
  console.log(`[${new Date().toISOString()}] GET /test called`);
  res.json({ success: true, message: "Hello World" });
});

/* =====================================================
   4. API verify request + sign response
===================================================== */
app.post("/verify-otp", ...shield.middlewares(), (req, res, next) => {
  try {
    const { otp } = req.body;

    if (otp !== "123456") {
      res.json({
        success: false,
        code: "INVALID_OTP",
        message: "Xac thuc OTP khong thanh cong",
      });
    } else {
      res.json({
        success: true,
        code: "OK",
        message: "Xac thuc OTP thanh cong",
      });
    }
  } catch (err) {
    next(err);
  }
});

/* =====================================================
   5. Error handler (phải đặt cuối cùng)
===================================================== */
app.use(shield.errorHandler());

/* =====================================================
   6. Graceful shutdown
===================================================== */
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down...");
  process.exit(0);
});
process.on("SIGINT", () => {
  console.log("SIGINT received, shutting down...");
  process.exit(0);
});

/* =====================================================
   7. Start server
===================================================== */
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});
