const express = require("express");
const Ticket = require("../models/Ticket");

const router = express.Router();

// GET all tickets
router.get("/", async (req, res) => {
  try {
    const tickets = await Ticket.find().sort({ createdAt: -1 });

    res.json({
      success: true,
      count: tickets.length,
      tickets,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch tickets",
      error: error.message,
    });
  }
});

// GET single ticket
router.get("/:id", async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);

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
    res.status(500).json({
      success: false,
      message: "Failed to fetch ticket",
      error: error.message,
    });
  }
});

// CREATE new ticket
router.post("/", async (req, res) => {
  try {
    const {
      ticketId,
      subject,
      sender,
      recipient,
      emailBody,
      category,
      priority,
      status,
      threatScore,
      aiConfidence,
      authentication,
      sourceIp,
      domain,
      indicators,
      assignedTeam,
      recommendedSolution,
    } = req.body;

    const ticket = new Ticket({
      ticketId,
      subject,
      sender,
      recipient,
      emailBody,
      category,
      priority,
      status,
      threatScore,
      aiConfidence,
      authentication,
      sourceIp,
      domain,
      indicators,
      assignedTeam,
      recommendedSolution,
    });

    const savedTicket = await ticket.save();

    res.status(201).json({
      success: true,
      message: "Ticket created successfully",
      ticket: savedTicket,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to create ticket",
      error: error.message,
    });
  }
});

// UPDATE ticket
router.put("/:id", async (req, res) => {
  try {
    const updatedTicket = await Ticket.findByIdAndUpdate(
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
        message: "Ticket not found",
      });
    }

    res.json({
      success: true,
      message: "Ticket updated successfully",
      ticket: updatedTicket,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to update ticket",
      error: error.message,
    });
  }
});

// DELETE ticket
router.delete("/:id", async (req, res) => {
  try {
    const deletedTicket = await Ticket.findByIdAndDelete(req.params.id);

    if (!deletedTicket) {
      return res.status(404).json({
        success: false,
        message: "Ticket not found",
      });
    }

    res.json({
      success: true,
      message: "Ticket deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to delete ticket",
      error: error.message,
    });
  }
});

module.exports = router;