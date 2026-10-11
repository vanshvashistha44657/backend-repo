const nodemailer = require("nodemailer");

let testSender;

function smtpConfigured(env = process.env) {
  return Boolean(env.SMTP_HOST && env.SMTP_PORT && env.SMTP_USER && env.SMTP_PASSWORD && env.MAIL_FROM);
}

function mailConfiguration(env = process.env) {
  return { configured: smtpConfigured(env), required: ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "MAIL_FROM", "PASSWORD_RESET_ORIGIN"] };
}

async function sendPasswordResetEmail({ to, name, token }) {
  const origin = String(process.env.PASSWORD_RESET_ORIGIN || process.env.FRONTEND_URLS || "").split(",")[0].replace(/\/$/, "");
  const url = `${origin}/reset-password?token=${encodeURIComponent(token)}`;
  const message = {
    from: process.env.MAIL_FROM,
    to,
    subject: "SentinelOps password reset",
    text: `Hello ${name || "there"},\n\nReset your password within 30 minutes:\n${url}\n\nIf you did not request this, ignore this email.`,
    html: `<p>Hello ${name || "there"},</p><p>Reset your password within 30 minutes:</p><p><a href="${url}">${url}</a></p><p>If you did not request this, ignore this email.</p>`,
  };
  if (testSender) return testSender(message);
  if (!smtpConfigured()) { const error = new Error("SMTP is not configured"); error.code = "SMTP_NOT_CONFIGURED"; throw error; }
  const transport = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT), secure: String(process.env.SMTP_SECURE).toLowerCase() === "true", auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD } });
  await transport.sendMail(message);
}

module.exports = { mailConfiguration, sendPasswordResetEmail, setTestSender: (fn) => { testSender = fn; } };
