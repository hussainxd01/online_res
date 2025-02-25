import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import connectDB from "../src/config/db.js";

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json()); // Body parser
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Parse cookies
app.use(cors({ origin: process.env.CLIENT_URL, credentials: true })); // CORS setup
app.use(morgan("dev")); // Logger

// Database connection
connectDB();

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
