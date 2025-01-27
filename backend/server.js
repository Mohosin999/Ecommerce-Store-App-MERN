import express from "express";
import dotenv from "dotenv";
// Routes
import authRoutes from "./routes/auth.route.js";
// DB Function
import { connectDB } from "./lib/db.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
// Authentication
app.use("/api/auth", authRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);

  connectDB();
});
