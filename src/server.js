require("dotenv").config();

const express = require("express");
const {
  CShield,
  DefaultRequestVerifier,
  DefaultResponseSigner,
  DefaultPublicKeyProvider,
  DefaultPrivateKeyProvider,
} = require("cshield-sdk");

const app = express();
app.use(express.json());

/* =====================================================
   1. Đọc key từ env var (base64-encoded PEM)
   Encode: base64 -w 0 private.pem
   Decode tự động tại runtime
===================================================== */
if (!process.env.CSHIELD_PRIVATE_KEY || !process.env.CSHIELD_PUBLIC_KEY) {
  console.error("Missing env vars: CSHIELD_PRIVATE_KEY, CSHIELD_PUBLIC_KEY");
  process.exit(1);
}

const privateKey = Buffer.from(
  process.env.CSHIELD_PRIVATE_KEY,
  "base64",
).toString("utf8");
const publicKey = Buffer.from(
  process.env.CSHIELD_PUBLIC_KEY,
  "base64",
).toString("utf8");

const privateKeyProvider = new DefaultPrivateKeyProvider(privateKey);
const publicKeyProvider = new DefaultPublicKeyProvider(publicKey);

/* =====================================================
   2. Khởi tạo CShield
===================================================== */
const shield = new CShield({
  requestVerifier: new DefaultRequestVerifier(publicKeyProvider),
  responseSigner: new DefaultResponseSigner(privateKeyProvider),
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
   6. Start server
===================================================== */
const PORT = process.env.PORT || 8080;
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
});
