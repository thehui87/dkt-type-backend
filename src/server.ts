import express from "express";
import dotenv from "dotenv";
import connectDB from "./db";
import authRoutes from "./routes/authRoutes";
import userRoutes from "./routes/userRoutes";
const cookieParser = require("cookie-parser");
const cors = require("cors");

dotenv.config();

const app = express();
app.use(
    cors({
        origin: "http://localhost:3000",
        credentials: true, // This allows cookies to be sent and received
    }),
);
app.use(cookieParser());
const port = 3001;

app.use(express.json());
connectDB();

app.use("/auth", authRoutes);
app.use("/users", userRoutes);

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
