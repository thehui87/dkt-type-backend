import express from "express";
import dotenv from "dotenv";
import connectDB from "./db";
import authRoutes from "./routes/authRoutes";
import userRoutes from "./routes/userRoutes";

dotenv.config();

const app = express();
const port = 3000;

app.use(express.json());
connectDB();

app.use("/auth", authRoutes);
app.use("/users", userRoutes);

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
