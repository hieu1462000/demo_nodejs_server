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
if (!process.env.CSHIELD_PRIVATE_KEY) {
  console.error("Missing env vars: CSHIELD_PRIVATE_KEY");
  process.exit(1);
}

if (!process.env.CSHIELD_LICENSE_KEY) {
  console.error("Missing env var: CSHIELD_LICENSE_KEY (raw license JWT string)");
  process.exit(1);
}

const privateKey = Buffer.from(
  process.env.CSHIELD_PRIVATE_KEY,
  "base64",
).toString("utf8");

const privateKeyProvider = new DefaultPrivateKeyProvider(privateKey);
const responseSigner = new DefaultResponseSigner(privateKeyProvider);
const requestVerifier = new DefaultRequestVerifier();

/* =====================================================
   3. API không cần verify / sign
===================================================== */
app.get("/test", (req, res) => {
  console.log(`[${new Date().toISOString()}] GET /test called`);
  res.json({ success: true, message: "Hello World" });
});


async function startServer() {
  let cshield;
  try {
    cshield = await CShield.create({
      license: {
        licenseKey: process.env.CSHIELD_LICENSE_KEY,
        gracePath: "./.cshield.grace",
        appId: { ios: "com.cmc.CShieldExampleApp", android: "com.example.c_shield_sample_app" },
        onStatusChange: (status) => {
          console.log(`[CShield] License status changed: ${status}`);
        },
        onRenew: async (newToken) => {
          console.log("[CShield] License renewed, new token persisted.");
          //TODO: save new token
        },
      },
    });
  } catch (err) {
    console.error("[CShield] License validation failed:", err.message);
    process.exit(1);
  }
  /* =====================================================
     4. API verify request + sign response
  ===================================================== */
  app.post("/verify-otp",
    cshield.verifyMiddleware(requestVerifier),
    cshield.signMiddleware(responseSigner),
    (req, res, next) => {
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
  app.use(cshield.errorHandler());

  /* =====================================================
    6. Graceful shutdown
  ===================================================== */
  process.on("SIGTERM", () => {
    console.log("[CShield] SIGTERM received, shutting down...");
    cshield.shutdown();
    process.exit(0);
  });
  process.on("SIGINT", () => {
    console.log("[CShield] SIGINT received, shutting down...");
    cshield.shutdown();
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
}

startServer().catch((err) => {
  console.error("Fatal startup error:", err);
  process.exit(1);
});