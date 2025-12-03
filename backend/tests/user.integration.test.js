const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../models/User');
const Contact = require('../models/Contact');
const jwt = require('jsonwebtoken');

// Mock the models
jest.mock('../models/User');
jest.mock('../models/Contact');
jest.mock('jsonwebtoken');

describe('User Management Endpoints', () => {
  let userToken;

  beforeAll(() => {
    // Mock the JWT verify method
    jwt.verify.mockImplementation((token, secret, callback) => {
      if (token === 'mock-jwt-token') {
        callback(null, { id: 'user-id' });  // Mock valid user ID
      } else {
        callback(new Error('Invalid token'), null);
      }
    });

    // Mock JWT token
    userToken = 'mock-jwt-token';
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('GET /api/users/profile', () => {
    it('should return user profile with valid token', async () => {
      const mockUser = {
        _id: 'user-id',
        email: 'test@example.com',
        username: 'testuser',
        publicKey: 'test-public-key',
        createdAt: new Date(),
        lastLogin: null
      };

      // Mock the query chain: findById().select()
      User.findById.mockReturnValue({
        select: jest.fn().mockResolvedValue(mockUser)
      });

      const response = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(200);
      expect(response.body.user).toHaveProperty('id', 'user-id');
      expect(response.body.user).toHaveProperty('email', 'test@example.com');
      expect(response.body.user).toHaveProperty('username', 'testuser');
      expect(response.body.user).toHaveProperty('publicKey', 'test-public-key');
      expect(response.body.user).toHaveProperty('createdAt');
      expect(response.body.user).toHaveProperty('lastLogin');
    });

    it('should return 404 if user not found', async () => {
      User.findById.mockReturnValue({
        select: jest.fn().mockResolvedValue(null)
      });

      const response = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(404);
      expect(response.body.message).toBe('User not found');
    });

    it('should return 401 without token', async () => {
      const response = await request(app)
        .get('/api/users/profile');

      expect(response.status).toBe(401);
    });

    it('should return 401 with invalid token', async () => {
      const response = await request(app)
        .get('/api/users/profile')
        .set('Authorization', 'Bearer invalid-token');

      expect(response.status).toBe(401);
    });
  });

  describe('GET /api/users/contacts', () => {
    it('should return user contacts with valid token', async () => {
      const mockContacts = [
        {
          contactUserId: {
            _id: 'contact-user-id',
            username: 'contactuser',
            publicKey: 'contact-public-key'
          },
          addedAt: new Date(),
          lastSeen: new Date(),
          isOnline: true
        }
      ];

      Contact.find.mockReturnValue({
        populate: jest.fn().mockReturnValue({
          select: jest.fn().mockResolvedValue(mockContacts)
        })
      });

      const response = await request(app)
        .get('/api/users/contacts')
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.contacts)).toBe(true);
      expect(response.body.contacts.length).toBeGreaterThan(0);
      expect(response.body.contacts[0]).toHaveProperty('id', 'contact-user-id');
      expect(response.body.contacts[0]).toHaveProperty('username', 'contactuser');
      expect(response.body.contacts[0]).toHaveProperty('publicKey', 'contact-public-key');
      expect(response.body.contacts[0]).toHaveProperty('addedAt');
      expect(response.body.contacts[0]).toHaveProperty('lastSeen');
      expect(response.body.contacts[0]).toHaveProperty('isOnline');
    });

    it('should return 401 without token', async () => {
      const response = await request(app)
        .get('/api/users/contacts');

      expect(response.status).toBe(401);
    });
  });

  describe('POST /api/users/add-contact', () => {
    it('should add contact successfully', async () => {
      const mockContactUser = {
        _id: 'new-contact-id',
        username: 'newcontact',
        publicKey: 'new-public-key'
      };

      User.findOne.mockResolvedValue(mockContactUser);
      Contact.findOne.mockResolvedValue(null);
      Contact.prototype.save = jest.fn().mockImplementation(function() {
        this.addedAt = new Date();
        return Promise.resolve(this);
      });

      const response = await request(app)
        .post('/api/users/add-contact')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ username: 'newcontact' });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.contact).toHaveProperty('id', 'new-contact-id');
      expect(response.body.contact).toHaveProperty('username', 'newcontact');
      expect(response.body.contact).toHaveProperty('publicKey', 'new-public-key');
      expect(response.body.contact).toHaveProperty('addedAt');
    });

    it('should return 400 if username is missing', async () => {
      const response = await request(app)
        .post('/api/users/add-contact')
        .set('Authorization', `Bearer ${userToken}`)
        .send({});

      expect(response.status).toBe(400);
      expect(response.body.message).toBe('Username is required');
    });

    it('should return 404 if user not found', async () => {
      User.findOne.mockResolvedValue(null);

      const response = await request(app)
        .post('/api/users/add-contact')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ username: 'nonexistentuser' });

      expect(response.status).toBe(404);
      expect(response.body.message).toBe('User not found');
    });

    it('should return 409 if contact already exists', async () => {
      User.findOne.mockResolvedValue({ _id: 'existing-id' });
      Contact.findOne.mockResolvedValue({ _id: 'existing-contact' });

      const response = await request(app)
        .post('/api/users/add-contact')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ username: 'existingcontact' });

      expect(response.status).toBe(409);
      expect(response.body.message).toBe('Contact already exists');
    });

    it('should return 401 without token', async () => {
      const response = await request(app)
        .post('/api/users/add-contact')
        .send({ username: 'testuser' });

      expect(response.status).toBe(401);
    });
  });
});
