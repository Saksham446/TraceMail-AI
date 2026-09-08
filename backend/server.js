const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const axios = require("axios");
require("dotenv").config();

const ticketRoutes = require("./routes/ticketRoutes");
const reportRoutes = require("./routes/reportRoutes");

const app = express();
const PORT = 5001;

// =========================================
// AI SERVICE CONFIGURATION
// =========================================

const AI_SERVICE_URL = "http://localhost:8000";

// =========================================
// MIDDLEWARE
// =========================================

app.use(cors());
app.use(express.json());

// =========================================
// API ROUTES
// =========================================

app.use("/api/tickets", ticketRoutes);
app.use("/api/reports", reportRoutes);

// =========================================
// AI ANALYSIS ROUTE
// =========================================

app.post("/api/ai/analyze", async (req, res) => {
  try {
    const emailData = req.body;

    console.log("🤖 Sending email to AI service...");

    const response = await axios.post(
      `${AI_SERVICE_URL}/analyze`,
      {
        subject: emailData.subject || "",
        sender: emailData.sender || "",
        body: emailData.body || "",
        spf: emailData.spf || "UNKNOWN",
        dkim: emailData.dkim || "UNKNOWN",
        dmarc: emailData.dmarc || "UNKNOWN",
        sourceIp: emailData.sourceIp || "",
        domain: emailData.domain || "",
      },
      {
        timeout: 15000,
      }
    );

    console.log("✅ AI analysis received successfully");

    res.json(response.data);
  } catch (error) {
    console.error("❌ AI service error:");

    if (error.response) {
      console.error(error.response.data);
    } else {
      console.error(error.message);
    }

    res.status(500).json({
      success: false,
      message: "AI analysis service is unavailable",
      error: error.message,
    });
  }
});

// =========================================
// MONGODB CONNECTION
// =========================================

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected successfully ✅");
  })
  .catch((error) => {
    console.error("MongoDB connection failed ❌");
    console.error(error.message);
  });

// =========================================
// HEALTH CHECK
// =========================================

app.get("/", (req, res) => {
  res.json({
    message: "TraceMail AI Backend is running 🚀",
    status: "success",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",
    aiService: AI_SERVICE_URL,
  });
});

// =========================================
// START SERVER
// =========================================

app.listen(PORT, () => {
  console.log(
    `TraceMail AI Backend running on http://localhost:${PORT}`
  );

  console.log(
    `TraceMail AI Service expected at ${AI_SERVICE_URL}`
  );
});