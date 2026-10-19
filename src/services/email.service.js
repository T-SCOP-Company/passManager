const nodemailer = require("nodemailer");

function createEmailService(config) {
  const transporter = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.secure,
    auth: { user: config.smtp.from, pass: config.smtp.password },
    tls: { minVersion: "TLSv1.2" },
  });

  return {
    verify: () => transporter.verify(),
    sendLoginCode: ({ to, code, expiresInMinutes }) => transporter.sendMail({
      from: `T-SCOP Secure Vault <${config.smtp.from}>`,
      to,
      subject: "Your T-SCOP verification code",
      text: `Your T-SCOP verification code is ${code}. It expires in ${expiresInMinutes} minutes. If you did not request this code, contact your administrator.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto"><h2>T-SCOP Secure Vault</h2><p>Use this one-time code to complete your sign-in:</p><p style="font-size:32px;font-weight:bold;letter-spacing:8px">${code}</p><p>This code expires in ${expiresInMinutes} minutes and can be used only once.</p><p>If you did not request this code, contact your administrator.</p></div>`,
    }),
  };
}

module.exports = { createEmailService };
