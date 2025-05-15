// createInitialAdmin.js

const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");

async function createInitialAdmin() {
  const uri = "YOUR_MONGODB_ATLAS_URI";
  const client = new MongoClient(uri);

  try {
    await client.connect();
    const db = client.db("assignment2"); // use your actual DB name
    const users = db.collection("users");

    const hashedPassword = await bcrypt.hash("AdminPassword123", 10);

    const adminUser = {
      username: "admin",
      email: "admin@example.com",
      password: hashedPassword,
      user_type: "admin"
    };

    const result = await users.insertOne(adminUser);
    console.log("✅ Admin user created:", result.insertedId);
  } catch (err) {
    console.error("❌ Failed to create admin:", err);
  } finally {
    await client.close();
  }
}

createInitialAdmin();
