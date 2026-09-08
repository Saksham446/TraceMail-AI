const mongoose = require("mongoose");

const ticketSchema = new mongoose.Schema(
  {
    ticketId: {
      type: String,
      unique: true,
      required: true,
    },

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
      enum: ["Low", "Medium", "High", "Critical"],
      default: "Medium",
    },

    status: {
      type: String,
      enum: ["Open", "Investigating", "Resolved"],
      default: "Open",
    },

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

module.exports = mongoose.model("Ticket", ticketSchema);