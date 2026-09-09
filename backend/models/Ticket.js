const mongoose = require("mongoose");

// =========================================
// AUDIT / CHAIN OF CUSTODY SCHEMA
// =========================================

const auditEventSchema = new mongoose.Schema(
  {
    action: {
      type: String,
      required: true,
      trim: true,
    },

    actor: {
      type: String,
      default: "TraceMail AI",
      trim: true,
    },

    details: {
      type: String,
      trim: true,
    },

    evidenceHash: {
      type: String,
      trim: true,
    },

    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    _id: false,
  }
);

// =========================================
// TICKET SCHEMA
// =========================================

const ticketSchema = new mongoose.Schema(
  {
    ticketId: {
      type: String,
      unique: true,
      required: true,
    },

    // =========================================
    // AUTOMATIC CASE CREATION
    // =========================================

    autoCreated: {
      type: Boolean,
      default: false,
      index: true,
    },

    caseType: {
      type: String,
      enum: ["Automatic", "Standard"],
      default: "Standard",
    },

    caseTrigger: {
      type: String,
      trim: true,
    },

    // =========================================
    // EVIDENCE INTEGRITY
    // =========================================

    evidenceHash: {
      type: String,
      trim: true,
      index: true,
    },

    hashAlgorithm: {
      type: String,
      default: "SHA-256",
    },

    // =========================================
    // CHAIN OF CUSTODY
    // =========================================

    auditTimeline: {
      type: [auditEventSchema],
      default: [],
    },

    // =========================================
    // EMAIL INFORMATION
    // =========================================

    subject: {
      type: String,
      required: true,
      trim: true,
    },

    sender: {
      type: String,
      required: true,
      trim: true,
    },

    recipient: {
      type: String,
      trim: true,
    },

    emailBody: {
      type: String,
      trim: true,
    },

    // =========================================
    // THREAT CLASSIFICATION
    // =========================================

    category: {
      type: String,
      enum: [
        "Phishing",
        "Malware",
        "Spam",
        "BEC / Fraud",
        "Credential Theft",
        "Suspicious",
        "Other",
      ],
      default: "Other",
    },

    priority: {
      type: String,
      enum: [
        "Low",
        "Medium",
        "High",
        "Critical",
      ],
      default: "Medium",
    },

    status: {
      type: String,
      enum: [
        "Open",
        "Investigating",
        "Resolved",
      ],
      default: "Open",
    },

    // =========================================
    // AI THREAT INTELLIGENCE
    // =========================================

    threatScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    aiConfidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    // =========================================
    // EMAIL AUTHENTICATION
    // =========================================

    authentication: {
      spf: {
        type: String,
        default: "UNKNOWN",
      },

      dkim: {
        type: String,
        default: "UNKNOWN",
      },

      dmarc: {
        type: String,
        default: "UNKNOWN",
      },
    },

    // =========================================
    // SOURCE INTELLIGENCE
    // =========================================

    sourceIp: {
      type: String,
      trim: true,
    },

    domain: {
      type: String,
      trim: true,
    },

    indicators: [
      {
        type: String,
        trim: true,
      },
    ],

    // =========================================
    // INVESTIGATION WORKFLOW
    // =========================================

    assignedTeam: {
      type: String,
      default: "Threat Intelligence",
    },

    recommendedSolution: {
      type: String,
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model(
  "Ticket",
  ticketSchema
);