const express = require("express");
const Report = require("../models/Report");

const {
  authenticateToken,
  authorizeRoles,
} = require("../middleware/authMiddleware");

const router = express.Router();

/*
  AUTHENTICATION
  All report routes require a valid JWT.
*/
router.use(authenticateToken);

/*
  GET ALL REPORTS
  Allowed: Admin, Analyst, Viewer
*/
router.get(
  "/",
  authorizeRoles("Admin", "Analyst", "Viewer"),
  async (req, res) => {
    try {
      const reports = await Report.find().sort({
        createdAt: -1,
      });

      res.json({
        success: true,
        count: reports.length,
        reports,
      });
    } catch (error) {
      console.error("Failed to fetch reports:", error);

      res.status(500).json({
        success: false,
        message: "Failed to fetch reports",
        error: error.message,
      });
    }
  },
);

/*
  GET SINGLE REPORT
  Allowed: Admin, Analyst, Viewer
*/
router.get(
  "/:id",
  authorizeRoles("Admin", "Analyst", "Viewer"),
  async (req, res) => {
    try {
      const report = await Report.findById(req.params.id);

      if (!report) {
        return res.status(404).json({
          success: false,
          message: "Report not found",
        });
      }

      res.json({
        success: true,
        report,
      });
    } catch (error) {
      console.error("Failed to fetch report:", error);

      res.status(500).json({
        success: false,
        message: "Failed to fetch report",
        error: error.message,
      });
    }
  },
);

/*
  CREATE REPORT
  Allowed: Admin, Analyst
  Viewer cannot generate reports.
*/
router.post(
  "/",
  authorizeRoles("Admin", "Analyst"),
  async (req, res) => {
    try {
      const {
        reportId,
        ticketId,
        title,
        type,
        classification,
        risk,
        score,
        confidence,
        sender,
        sourceIp,
        domain,
        indicators,
        assignedTeam,
        description,
        authentication,
        status,
      } = req.body;

      const report = new Report({
        reportId,
        ticketId,
        title,
        type,
        classification,
        risk,
        score,
        confidence,
        sender,
        sourceIp,
        domain,
        indicators,
        assignedTeam,
        description,
        authentication,
        status: status || "Ready",
      });

      const savedReport = await report.save();

      res.status(201).json({
        success: true,
        message: "Report created successfully",
        report: savedReport,
      });
    } catch (error) {
      console.error("Failed to create report:", error);

      res.status(500).json({
        success: false,
        message: "Failed to create report",
        error: error.message,
      });
    }
  },
);

/*
  UPDATE REPORT
  Allowed: Admin, Analyst
*/
router.put(
  "/:id",
  authorizeRoles("Admin", "Analyst"),
  async (req, res) => {
    try {
      const updatedReport =
        await Report.findByIdAndUpdate(
          req.params.id,
          req.body,
          {
            new: true,
            runValidators: true,
          },
        );

      if (!updatedReport) {
        return res.status(404).json({
          success: false,
          message: "Report not found",
        });
      }

      res.json({
        success: true,
        message: "Report updated successfully",
        report: updatedReport,
      });
    } catch (error) {
      console.error("Failed to update report:", error);

      res.status(500).json({
        success: false,
        message: "Failed to update report",
        error: error.message,
      });
    }
  },
);

/*
  DELETE REPORT
  Allowed: Admin only
*/
router.delete(
  "/:id",
  authorizeRoles("Admin"),
  async (req, res) => {
    try {
      const deletedReport =
        await Report.findByIdAndDelete(
          req.params.id,
        );

      if (!deletedReport) {
        return res.status(404).json({
          success: false,
          message: "Report not found",
        });
      }

      res.json({
        success: true,
        message: "Report deleted successfully",
      });
    } catch (error) {
      console.error("Failed to delete report:", error);

      res.status(500).json({
        success: false,
        message: "Failed to delete report",
        error: error.message,
      });
    }
  },
);

module.exports = router;