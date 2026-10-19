const required = ["MONGO_URI", "JWT_SECRET", "VAULT_MASTER_KEY"];

function loadConfig() {
  const production = process.env.NODE_ENV === "production";
  const smtpNames = production
    ? ["EMAIL_FROM", "EMAIL_PASSWORD", "EMAIL_HOST", "EMAIL_PORT"]
    : ["SMTP_DEV_FROM", "SMTP_DEV_PASSWORD", "SMTP_DEV_HOST", "SMTP_DEV_PORT"];
  const missing = [...required, ...smtpNames].filter((name) => !process.env[name]);
  if (missing.length) throw new Error(`Missing environment variables: ${missing.join(", ")}`);

  const masterKey = Buffer.from(process.env.VAULT_MASTER_KEY, "base64");
  if (masterKey.length !== 32) throw new Error("VAULT_MASTER_KEY must decode to exactly 32 bytes");
  if (process.env.JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters");

  return {
    port: Number(process.env.PORT || 11000),
    mongoUri: process.env.MONGO_URI,
    jwtSecret: process.env.JWT_SECRET,
    masterKey,
    production,
    appOrigin: process.env.APP_ORIGIN || "http://localhost:11000",
    itToolsOrigin: process.env.IT_TOOLS_ORIGIN || "https://it-tools.tech",
    smtp: {
      from: production ? process.env.EMAIL_FROM : process.env.SMTP_DEV_FROM,
      password: production ? process.env.EMAIL_PASSWORD : process.env.SMTP_DEV_PASSWORD,
      host: production ? process.env.EMAIL_HOST : process.env.SMTP_DEV_HOST,
      port: Number(production ? process.env.EMAIL_PORT : process.env.SMTP_DEV_PORT),
      secure: Number(production ? process.env.EMAIL_PORT : process.env.SMTP_DEV_PORT) === 465,
    },
  };
}

module.exports = { loadConfig };
