const mongoose = require("mongoose");

const reportSchema = new mongoose.Schema(
  {
    reportId: {
      type: String,
      unique: true,
      required: true,
    },

    ticketId: {
      type: String,
      required: true,
    },

    title: {
      type: String,
      required: true,
      trim: true,
    },

    type: {
      type: String,
      enum: [
        "Forensic Report",
        "Threat Report",
        "Incident Report",
        "Intelligence Report",
      ],
      default: "Forensic Report",
    },

    classification: {
      type: String,
      default: "Suspicious",
    },

    risk: {
      type: String,
      enum: ["Low", "Medium", "High", "Critical"],
      default: "Medium",
    },

    score: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    confidence: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    sender: {
      type: String,
      trim: true,
    },

    sourceIp: {
      type: String,
      trim: true,
    },

    domain: {
      type: String,
      trim: true,
    },

    indicators: {
      type: Number,
      default: 0,
    },

    assignedTeam: {
      type: String,
      default: "Threat Intelligence",
    },

    description: {
      type: String,
      trim: true,
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

    status: {
      type: String,
      default: "Ready",
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("Report", reportSchema);