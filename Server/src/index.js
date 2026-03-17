import dotenv from "dotenv";
import { app } from "./app.js";
import connectDB from "./db/index.js";

dotenv.config({
  path: "./.env"
});

// ✅ Use Railway's port
const PORT = process.env.PORT || 3000;

connectDB()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`); // Fix log formatting
    });
  })
  .catch((err) => {
    console.error("MongoDB connection error:", err);
  });