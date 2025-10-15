import { Request, Response } from "express";
import express from 'express';
import morgan from 'morgan';
import dotenv from 'dotenv';
import helmet from "helmet";
import cors from "cors";
import authRoutes from './routes/auth'
import { connectDB } from "./config/database";
import errorHandler from "./middleware/errorHandler";

dotenv.config();
connectDB();
const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan("dev"));
app.use(express.json());

app.get("/api/v1", (req: Request, res: Response) => {
  res.status(200).json({
    status: "OK",
    timeStamp: new Date().toISOString(),
  });
});
app.use("/api/v1/auth", authRoutes)

app.use(errorHandler)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`${PORT} listen server`);
});
