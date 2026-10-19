require("dotenv").config();
const argon2 = require("argon2");
const { loadConfig } = require("../src/config");
const { connectDB, disconnectDB } = require("../src/database/connection");
const Organization = require("../src/models/organization.model");
const User = require("../src/models/user.model");
const VaultItem = require("../src/models/vaultItem.model");

async function bootstrap() {
  const config = loadConfig();
  const email = String(process.env.BOOTSTRAP_ADMIN_EMAIL || "").trim().toLowerCase();
  const password = String(process.env.BOOTSTRAP_ADMIN_PASSWORD || "");
  if (!email || password.length < 14) throw new Error("Set BOOTSTRAP_ADMIN_EMAIL and a BOOTSTRAP_ADMIN_PASSWORD of at least 14 characters");
  await connectDB(config.mongoUri);
  const organization = await Organization.findOneAndUpdate(
    { slug: "t-scop" },
    { $set: { name: "T-SCOP", primaryDomain: "t-scop.com", status: "active" } },
    { upsert: true, new: true }
  );
  await VaultItem.updateMany(
    { organizationId: organization._id, vaultType: { $exists: false } },
    [{ $set: { vaultType: { $cond: [{ $ne: [{ $ifNull: ["$ownerUserId", null] }, null] }, "personal", "company"] } } }]
  );
  const existing = await User.findOne({ organizationId: organization._id, email });
  if (existing) {
    console.log(`T-SCOP is ready; super administrator ${email} already exists`);
  } else {
    await User.create({
      organizationId: organization._id, firstName: "T-SCOP", lastName: "Administrator",
      email, role: "superAdmin", passwordHash: await argon2.hash(password, { type: argon2.argon2id }),
    });
    console.log(`Created T-SCOP and super administrator ${email}`);
  }
  await disconnectDB();
}

bootstrap().catch(async (error) => { console.error(error.message); await disconnectDB(); process.exit(1); });
