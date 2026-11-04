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
  // Gốc URL JWKS KHÔNG cấu hình được — bake trong gói SDK (pack:uat/pack:prod). Xem SDK README §1.1.
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
   4b. Route demo cho trust nâng cao (để test client ensureTrust / requireFresh)
   - /payment  : đòi trust >= L4 → client phải CShieldSDK.ensureTrust(L4) (upgrade Play Integrity)
       trước khi gọi, nếu không sẽ 403 CSHIELD_DEVICE_NOT_ALLOWED.
   - /transfer : đòi L4 + attestation TƯƠI trong 5 phút (maxTrustAgeSeconds) → client phải
       ensureTrust(L4, requireFresh=true); trust cũ/thiếu `fresh` → 403 CSHIELD_TRUST_NOT_FRESH.
   Override theo env nếu cần: CSHIELD_SENSITIVE_MIN_TRUST / CSHIELD_SENSITIVE_MAX_AGE.
===================================================== */
const SENSITIVE_MIN_TRUST = process.env.CSHIELD_SENSITIVE_MIN_TRUST || "L4";
const SENSITIVE_MAX_AGE = Number(process.env.CSHIELD_SENSITIVE_MAX_AGE || 300);

app.post("/payment", ...shield.middlewares({ minTrustLevel: SENSITIVE_MIN_TRUST }), (req, res) => {
  res.json({ success: true, code: "OK", message: "Payment authorized (trust >= L4)" });
});

app.post(
  "/transfer",
  ...shield.middlewares({ minTrustLevel: SENSITIVE_MIN_TRUST, maxTrustAgeSeconds: SENSITIVE_MAX_AGE }),
  (req, res) => {
    res.json({ success: true, code: "OK", message: "Transfer authorized (fresh L4)" });
  }
);

/* =====================================================
   4c. [CHẨN ĐOÁN] Log chi tiết khi verify request FAIL — đặt TRƯỚC shield.errorHandler().
   Mục đích: khi gặp CSHIELD_INVALID_REQUEST_SIGNATURE với client iOS, phân biệt 3 khả năng:
     (a) server (bản deploy) chưa có nhánh iOS  → platform in ra KHÁC "ios" dù token có plt=ios
     (b) token thiếu/không phải plt="ios"        → "plt" in ra undefined/khác ios (lỗi BE/đăng ký)
     (c) canonical/bodyHash lệch                 → plt=ios nhưng vẫn fail → soi canonical 2 bên
   CHỈ decode phần PAYLOAD (base64url) của access token trong cs-proof — KHÔNG verify chữ ký, KHÔNG
   cần secret. Thuần đọc để log; có thể xoá sau khi xong. Không làm lộ gì hơn chính token client gửi.
===================================================== */
function decodeJwtPayload(jwt) {
  try {
    const part = String(jwt).split(".")[1];
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

app.use((err, req, res, next) => {
  const code = err && (err.code || err.name);
  // Chỉ quan tâm lỗi liên quan verify chữ ký / thiết bị.
  if (code && String(code).toUpperCase().includes("SIGNATURE")) {
    try {
      const proofHeader = req.header("cs-proof");
      const proof = proofHeader
        ? JSON.parse(Buffer.from(proofHeader, "base64").toString("utf8"))
        : null;
      const tok = proof ? decodeJwtPayload(proof.accessToken) : null;
      const crypto = require("crypto");
      const raw = req.rawBody;
      const bodyHash = Buffer.isBuffer(raw)
        ? crypto.createHash("sha256").update(raw).digest("hex")
        : "(no rawBody)";
      const qIndex = req.originalUrl.indexOf("?");
      const path = qIndex === -1 ? req.originalUrl : req.originalUrl.slice(0, qIndex);
      const rawQuery = qIndex === -1 ? "" : req.originalUrl.slice(qIndex + 1);
      // Dựng canonical GIỐNG buildCanonicalRequest của SDK: METHOD\nPATH\nQUERY\nTS\nREQID\nbodyHash.
      // (QUERY ở demo /verify-otp là rỗng; vẫn giữ dòng rỗng cho khớp.)
      const serverCanonical = [
        req.method,
        path,
        rawQuery, // demo không canonical-hoá vì không query; đủ để đối chiếu
        proof ? proof.timestamp : "",
        proof ? proof.requestId : "",
        bodyHash,
      ].join("\n");
      const serverRequestHash = crypto.createHash("sha256").update(Buffer.from(serverCanonical, "utf8")).digest("hex");
      const hashMatch = proof && proof.requestHash
        ? (serverRequestHash === String(proof.requestHash) ? "KHỚP ✅" : "LỆCH ❌")
        : "?";
      console.warn("=== [CShield DIAG] verify FAILED ===");
      console.warn("  error      :", code, "-", err.message);
      console.warn("  token.plt  :", tok ? tok.plt : "(decode fail)", "  (nhánh iOS CHỈ chạy khi === 'ios')");
      console.warn("  token.lvl  :", tok ? (tok.lvl || tok.tl) : "?", "  sub:", tok ? tok.sub : "?");
      console.warn("  token.cnf  :", tok && tok.cnf ? "có cnf.jwk" : "THIẾU cnf.jwk");
      console.warn("  server method        :", req.method);
      console.warn("  server canonical path:", JSON.stringify(path), " query:", JSON.stringify(rawQuery));
      console.warn("  server bodyHash(hex) :", bodyHash);
      console.warn("  proof.timestamp      :", proof ? proof.timestamp : "?", " requestId:", proof ? proof.requestId : "?");
      console.warn("  client requestHash   :", proof ? proof.requestHash : "?");
      console.warn("  server requestHash   :", serverRequestHash, "→ canonical", hashMatch);
      console.warn("====================================");
    } catch (logErr) {
      console.warn("[CShield DIAG] không log được chi tiết:", logErr && logErr.message);
    }
  }
  next(err);
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
