require("dotenv").config();
const { loadConfig } = require("./config");
const { connectDB, disconnectDB } = require("./database/connection");
const { createApp } = require("./app");

async function start() {
  const config = loadConfig();
  await connectDB(config.mongoUri);
  const server = createApp(config).listen(config.port, () => {
    console.log(`T-SCOP Password Manager listening on port ${config.port}`);
  });
  const shutdown = (signal) => {
    console.log(`${signal} received; shutting down`);
    server.close(async () => { await disconnectDB(); process.exit(0); });
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

start().catch((error) => { console.error("Startup failed", error); process.exit(1); });
