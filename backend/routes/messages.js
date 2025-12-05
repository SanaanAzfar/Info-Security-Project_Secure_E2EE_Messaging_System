const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { getMessages, sendMessage } = require('../controllers/messageController');

const router = express.Router();

/**
 * @swagger
 * /api/messages/{contactId}:
 *   get:
 *     summary: Retrieve message history with specific contact
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: contactId
 *         required: true
 *         schema:
 *           type: string
 *         description: The contact's user ID
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *         description: Number of messages to retrieve
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *         description: Number of messages to skip
 *       - in: query
 *         name: before
 *         schema:
 *           type: string
 *         description: Retrieve messages before this message ID
 *     responses:
 *       200:
 *         description: Message history retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 messages:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       senderId:
 *                         type: string
 *                       receiverId:
 *                         type: string
 *                       encryptedContent:
 *                         type: string
 *                       iv:
 *                         type: string
 *                       authTag:
 *                         type: string
 *                       nonce:
 *                         type: string
 *                       timestamp:
 *                         type: string
 *                       signature:
 *                         type: string
 *                       messageType:
 *                         type: string
 *                 hasMore:
 *                   type: boolean
 *                 total:
 *                   type: integer
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Contact not found
 *       500:
 *         description: Server error
 */
router.get('/:contactId', authenticateToken, getMessages);

/**
 * @swagger
 * /api/messages/send:
 *   post:
 *     summary: Send encrypted message
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - receiverId
 *               - encryptedContent
 *               - iv
 *               - authTag
 *               - nonce
 *               - timestamp
 *               - signature
 *             properties:
 *               receiverId:
 *                 type: string
 *                 description: The receiver's user ID
 *               encryptedContent:
 *                 type: string
 *                 description: Base64 encoded encrypted content
 *               iv:
 *                 type: string
 *                 description: Base64 encoded initialization vector
 *               authTag:
 *                 type: string
 *                 description: Base64 encoded authentication tag
 *               nonce:
 *                 type: string
 *                 description: Base64 encoded nonce
 *               timestamp:
 *                 type: string
 *                 description: ISO 8601 timestamp
 *               signature:
 *                 type: string
 *                 description: Base64 encoded signature
 *               messageType:
 *                 type: string
 *                 enum: [text, file]
 *                 default: text
 *                 description: Type of message
 *               sequenceNumber:
 *                 type: integer
 *                 description: Sequence number for message ordering
 *     responses:
 *       201:
 *         description: Message sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 messageId:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                 sequenceNumber:
 *                   type: integer
 *       400:
 *         description: Bad request - missing required fields
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Contact not found
 *       500:
 *         description: Server error
 */
router.post('/send', authenticateToken, sendMessage);

module.exports = router;
