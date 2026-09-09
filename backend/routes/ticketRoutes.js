const express = require("express");
const Ticket = require("../models/Ticket");

const {
  authenticateToken,
  authorizeRoles,
} = require("../middleware/authMiddleware");

const router = express.Router();


// =========================================
// AUTHENTICATION
// =========================================
// Every ticket API request requires a valid JWT.

router.use(authenticateToken);


// =========================================
// GET ALL TICKETS
// =========================================
// Allowed:
// Admin
// Analyst
// Viewer

router.get(
  "/",
  authorizeRoles(
    "Admin",
    "Analyst",
    "Viewer"
  ),
  async (req, res) => {
    try {
      const tickets = await Ticket.find()
        .sort({ createdAt: -1 });

      res.json({
        success: true,
        count: tickets.length,
        tickets,
      });

    } catch (error) {

      console.error(
        "❌ Failed to fetch tickets:",
        error.message
      );

      res.status(500).json({
        success: false,
        message: "Failed to fetch tickets",
        error: error.message,
      });

    }
  }
);


// =========================================
// GET SINGLE TICKET
// =========================================
// Allowed:
// Admin
// Analyst
// Viewer

router.get(
  "/:id",
  authorizeRoles(
    "Admin",
    "Analyst",
    "Viewer"
  ),
  async (req, res) => {
    try {

      const ticket =
        await Ticket.findById(
          req.params.id
        );

      if (!ticket) {

        return res.status(404).json({
          success: false,
          message: "Ticket not found",
        });

      }

      res.json({
        success: true,
        ticket,
      });

    } catch (error) {

      console.error(
        "❌ Failed to fetch ticket:",
        error.message
      );

      res.status(500).json({
        success: false,
        message: "Failed to fetch ticket",
        error: error.message,
      });

    }
  }
);


// =========================================
// CREATE NEW TICKET
// =========================================
// Allowed:
// Admin
// Analyst
//
// Viewer CANNOT create tickets.

router.post(
  "/",
  authorizeRoles(
    "Admin",
    "Analyst"
  ),
  async (req, res) => {

    try {

      const {
        ticketId,

        // Email information
        subject,
        sender,
        recipient,
        emailBody,

        // Threat information
        category,
        priority,
        status,
        threatScore,
        aiConfidence,

        // Automatic case creation
        autoCreated,
        caseType,
        caseTrigger,

        // Authentication
        authentication,

        // Source intelligence
        sourceIp,
        domain,

        // Threat indicators
        indicators,

        // Assignment
        assignedTeam,
        recommendedSolution,

        // Evidence integrity
        evidenceHash,
        hashAlgorithm,

      } = req.body;


      // =========================================
      // DETERMINE CASE TYPE SAFELY
      // =========================================

      const isAutomaticCase =
        autoCreated === true ||
        caseType === "Automatic";


      const finalCaseType =
        isAutomaticCase
          ? "Automatic"
          : "Standard";


      const finalCaseTrigger =
        caseTrigger ||
        (
          isAutomaticCase
            ? `Automatically created because threat severity is ${
                priority || "High"
              } with a threat score of ${
                threatScore ?? 0
              }/100.`
            : "Created as a standard investigation record."
        );


      // =========================================
      // CHAIN OF CUSTODY TIMELINE
      // =========================================

      const auditTimeline = [];


      // -----------------------------------------
      // 1. Evidence Received
      // -----------------------------------------

      auditTimeline.push({

        action: "Evidence Received",

        actor: "TraceMail AI",

        details:
          "Email evidence was received and prepared for forensic analysis.",

        evidenceHash:
          evidenceHash || "",

        timestamp: new Date(),

      });


      // -----------------------------------------
      // 2. SHA-256 Hash Generated
      // -----------------------------------------

      if (evidenceHash) {

        auditTimeline.push({

          action:
            "SHA-256 Evidence Hash Generated",

          actor:
            "TraceMail AI",

          details:
            "A cryptographic SHA-256 fingerprint was generated for the submitted email evidence.",

          evidenceHash,

          timestamp: new Date(),

        });

      }


      // -----------------------------------------
      // 3. AI Analysis Completed
      // -----------------------------------------

      auditTimeline.push({

        action:
          "AI Analysis Completed",

        actor:
          "TraceMail Explainable Threat Intelligence Engine",

        details:
          `Threat analysis completed with a score of ${
            threatScore ?? 0
          }/100 and ${
            aiConfidence ?? 0
          }% confidence.`,

        evidenceHash:
          evidenceHash || "",

        timestamp: new Date(),

      });


      // =========================================
      // 4. AUTOMATIC CASE CREATION
      // =========================================

      if (isAutomaticCase) {

        auditTimeline.push({

          action:
            "Automatic Case Created",

          actor:
            "TraceMail Automatic Case Engine",

          details:
            finalCaseTrigger,

          evidenceHash:
            evidenceHash || "",

          timestamp: new Date(),

        });

      }


      // =========================================
      // CREATE TICKET
      // =========================================

      const ticket =
        new Ticket({

          ticketId,

          subject,
          sender,
          recipient,
          emailBody,

          category,
          priority,

          // Automatic cases start as Open.
          // Standard investigations retain
          // the status sent by the frontend.

          status:
            isAutomaticCase
              ? "Open"
              : status || "Investigating",

          threatScore,
          aiConfidence,

          // Automatic case metadata

          autoCreated:
            isAutomaticCase,

          caseType:
            finalCaseType,

          caseTrigger:
            finalCaseTrigger,

          authentication,

          sourceIp,
          domain,

          indicators,

          assignedTeam,
          recommendedSolution,

          // =========================================
          // STORE EVIDENCE HASH
          // =========================================

          evidenceHash,

          hashAlgorithm:
            hashAlgorithm || "SHA-256",

          // =========================================
          // STORE CHAIN OF CUSTODY
          // =========================================

          auditTimeline,

        });


      // =========================================
      // SAVE TICKET
      // =========================================

      const savedTicket =
        await ticket.save();


      // =========================================
      // ADD TICKET CREATED EVENT
      // =========================================

      savedTicket.auditTimeline.push({

        action:
          "Ticket Created",

        actor:
          "TraceMail AI Backend",

        details:
          `Forensic ticket ${ticketId} was created and stored in the investigation database.`,

        evidenceHash:
          evidenceHash || "",

        timestamp: new Date(),

      });


      await savedTicket.save();


      // =========================================
      // RESPONSE
      // =========================================

      res.status(201).json({

        success: true,

        message:
          isAutomaticCase
            ? "Automatic case created successfully"
            : "Ticket created successfully",

        caseCreation: {

          type:
            finalCaseType,

          automatic:
            isAutomaticCase,

          ticketId,

          trigger:
            finalCaseTrigger,

        },

        ticket:
          savedTicket,

      });

    } catch (error) {

      console.error(
        "❌ Failed to create ticket:",
        error.message
      );

      res.status(500).json({

        success: false,

        message:
          "Failed to create ticket",

        error:
          error.message,

      });

    }

  }
);


// =========================================
// UPDATE TICKET
// =========================================
// Allowed:
// Admin
// Analyst
//
// Viewer CANNOT update tickets.

router.put(
  "/:id",
  authorizeRoles(
    "Admin",
    "Analyst"
  ),
  async (req, res) => {

    try {

      const updatedTicket =
        await Ticket.findByIdAndUpdate(

          req.params.id,

          req.body,

          {
            new: true,
            runValidators: true,
          }

        );


      if (!updatedTicket) {

        return res.status(404).json({

          success: false,

          message:
            "Ticket not found",

        });

      }


      res.json({

        success: true,

        message:
          "Ticket updated successfully",

        ticket:
          updatedTicket,

      });

    } catch (error) {

      console.error(
        "❌ Failed to update ticket:",
        error.message
      );

      res.status(500).json({

        success: false,

        message:
          "Failed to update ticket",

        error:
          error.message,

      });

    }

  }
);


// =========================================
// DELETE TICKET
// =========================================
// Allowed:
// Admin ONLY
//
// Analyst and Viewer cannot delete tickets.

router.delete(
  "/:id",
  authorizeRoles(
    "Admin"
  ),
  async (req, res) => {

    try {

      const deletedTicket =
        await Ticket.findByIdAndDelete(
          req.params.id
        );


      if (!deletedTicket) {

        return res.status(404).json({

          success: false,

          message:
            "Ticket not found",

        });

      }


      res.json({

        success: true,

        message:
          "Ticket deleted successfully",

      });

    } catch (error) {

      console.error(
        "❌ Failed to delete ticket:",
        error.message
      );

      res.status(500).json({

        success: false,

        message:
          "Failed to delete ticket",

        error:
          error.message,

      });

    }

  }
);


module.exports = router;