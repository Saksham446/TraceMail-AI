const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const axios = require("axios");
const crypto = require("crypto");
require("dotenv").config();

const ticketRoutes = require("./routes/ticketRoutes");
const reportRoutes = require("./routes/reportRoutes");
const authRoutes = require("./routes/authRoutes");

const {
  authenticateToken,
  authorizeRoles,
} = require("./middleware/authMiddleware");

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
// EVIDENCE HASHING
// =========================================

/**
 * Generates a SHA-256 digital fingerprint
 * for the supplied email evidence.
 *
 * The same email content always produces
 * the same hash. Any change in the content
 * produces a different hash.
 */
function generateEvidenceHash(emailContent) {
  return crypto
    .createHash("sha256")
    .update(emailContent, "utf8")
    .digest("hex");
}

// =========================================
// API ROUTES
// =========================================

// -----------------------------------------
// Authentication
// -----------------------------------------

app.use("/api/auth", authRoutes);


// -----------------------------------------
// Investigation tickets
// -----------------------------------------
// ticketRoutes already contains JWT
// authentication + role authorization.

app.use(
  "/api/tickets",
  ticketRoutes
);


// -----------------------------------------
// Reports
// -----------------------------------------

app.use(
  "/api/reports",
  reportRoutes
);


// =========================================
// AI ANALYSIS ROUTE
// =========================================
// Allowed roles:
// Admin
// Analyst
//
// Viewer is NOT allowed.
//
// Every request must contain a valid JWT.

app.post(
  "/api/ai/analyze",

  authenticateToken,

  authorizeRoles(
    "Admin",
    "Analyst"
  ),

  async (req, res) => {

    try {

      const emailData = req.body;

      console.log(
        `🤖 AI analysis requested by ${req.user.role}: ${req.user.email}`
      );


      // =========================================
      // NORMALIZE ATTACHMENTS
      // =========================================
      // Only attachment metadata is processed.
      // The actual file content is not stored here.

      const attachments = Array.isArray(
        emailData.attachments
      )
        ? emailData.attachments
        : [];


      // =========================================
      // CREATE CANONICAL EMAIL EVIDENCE
      // =========================================

      const evidenceContent = [

        `Subject: ${emailData.subject || ""}`,

        `From: ${emailData.sender || ""}`,

        `To: ${
          emailData.recipient ||
          emailData.to ||
          ""
        }`,

        `Body: ${emailData.body || ""}`,

        `SPF: ${
          emailData.spf ||
          "UNKNOWN"
        }`,

        `DKIM: ${
          emailData.dkim ||
          "UNKNOWN"
        }`,

        `DMARC: ${
          emailData.dmarc ||
          "UNKNOWN"
        }`,

        `Source IP: ${
          emailData.sourceIp ||
          ""
        }`,

        `Domain: ${
          emailData.domain ||
          ""
        }`,

        // -----------------------------------------
        // ATTACHMENT EVIDENCE
        // -----------------------------------------

        `Attachments: ${
          JSON.stringify(attachments)
        }`,

      ].join("\n");


      // =========================================
      // GENERATE SHA-256 EVIDENCE HASH
      // =========================================

      const evidenceHash =
        generateEvidenceHash(
          evidenceContent
        );


      console.log(
        "🔐 Evidence SHA-256 hash generated:"
      );

      console.log(
        evidenceHash
      );


      // =========================================
      // ATTACHMENT FORENSICS LOG
      // =========================================

      if (attachments.length > 0) {

        console.log(
          `📎 ${attachments.length} attachment(s) received for forensic analysis`
        );

      } else {

        console.log(
          "📎 No attachments received"
        );

      }


      // =========================================
      // SEND EMAIL TO AI SERVICE
      // =========================================

      const response =
        await axios.post(

          `${AI_SERVICE_URL}/analyze`,

          {

            subject:
              emailData.subject ||
              "",

            sender:
              emailData.sender ||
              "",

            body:
              emailData.body ||
              "",

            spf:
              emailData.spf ||
              "UNKNOWN",

            dkim:
              emailData.dkim ||
              "UNKNOWN",

            dmarc:
              emailData.dmarc ||
              "UNKNOWN",

            sourceIp:
              emailData.sourceIp ||
              "",

            domain:
              emailData.domain ||
              "",

            // -----------------------------------------
            // ATTACHMENT FORENSICS DATA
            // -----------------------------------------

            attachments:
              attachments,

          },

          {
            timeout: 15000,
          }

        );


      console.log(
        "✅ AI analysis received successfully"
      );


      // =========================================
      // RETURN AI RESULT + EVIDENCE HASH
      // =========================================

      res.json({

        ...response.data,

        evidence: {

          hashAlgorithm:
            "SHA-256",

          evidenceHash:
            evidenceHash,

          integrityStatus:
            "Verified",

        },

      });

    } catch (error) {

      console.error(
        "❌ AI service error:"
      );


      if (error.response) {

        console.error(
          error.response.data
        );

      } else {

        console.error(
          error.message
        );

      }


      res.status(500).json({

        success: false,

        message:
          "AI analysis service is unavailable",

        error:
          error.message,

      });

    }

  }
);


// =========================================
// MONGODB CONNECTION
// =========================================

mongoose
  .connect(process.env.MONGO_URI)

  .then(() => {

    console.log(
      "MongoDB connected successfully ✅"
    );

  })

  .catch((error) => {

    console.error(
      "MongoDB connection failed ❌"
    );

    console.error(
      error.message
    );

  });


// =========================================
// HEALTH CHECK
// =========================================

app.get("/", (req, res) => {

  res.json({

    message:
      "TraceMail AI Backend is running 🚀",

    status:
      "success",

    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected",

    aiService:
      AI_SERVICE_URL,

    authentication:
      "enabled",

    rbac:
      "enabled",

    attachmentForensics:
      "enabled",

  });

});


// =========================================
// START SERVER
// =========================================

app.listen(
  PORT,
  () => {

    console.log(
      `TraceMail AI Backend running on http://localhost:${PORT}`
    );

    console.log(
      `TraceMail AI Service expected at ${AI_SERVICE_URL}`
    );

    console.log(
      "🔐 Authentication routes available at /api/auth"
    );

    console.log(
      "🛡️ Backend RBAC protection enabled"
    );

    console.log(
      "📎 Attachment Forensics forwarding enabled"
    );

  }
);