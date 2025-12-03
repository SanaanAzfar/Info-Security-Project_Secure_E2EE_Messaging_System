const request = require('supertest');
const app = require('../app');
const User = require('../models/User');

// Mock the email service
jest.mock('../utils/emailService', () => ({
  sendOTPEmail: jest.fn(),
}));

describe('Authentication Integration Tests', () => {
  describe('POST /register', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('message', 'User registered successfully');

      // Verify user was created in database
      const user = await User.findOne({ email: userData.email });
      expect(user).toBeTruthy();
      expect(user.username).toBe(userData.username);
      expect(user.email).toBe(userData.email);
    });

    it('should return 400 for missing required fields', async () => {
      const response = await request(app)
        .post('/auth/register')
        .send({ username: 'testuser' })
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Username, email, and password are required');
    });

    it('should return 400 for existing user', async () => {
      const userData = {
        username: 'existinguser',
        email: 'existing@example.com',
        password: 'password123'
      };

      // Create user first
      await User.create(userData);

      // Try to register again
      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'User already exists');
    });

    it('should return 400 for invalid username length', async () => {
      const userData = {
        username: 'ab', // too short
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Username must be between 3 and 50 characters');
    });

    it('should return 400 for weak password', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: '12345' // too short
      };

      const response = await request(app)
        .post('/auth/register')
        .send(userData)
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Password must be at least 6 characters long');
    });
  });

  describe('POST /login', () => {
    beforeEach(async () => {
      // Create a test user for login tests
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };
      await User.create(userData);
    });

    it('should send OTP successfully with username', async () => {
      const loginData = {
        identifier: 'testuser',
        password: 'password123'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty('message', 'OTP sent to your email');

      // Verify OTP was set in database
      const user = await User.findOne({ username: 'testuser' }).select('+otp +otpExpires');
      expect(user).toHaveProperty('otp');
      expect(user).toHaveProperty('otpExpires');
    });

    it('should send OTP successfully with email', async () => {
      const loginData = {
        identifier: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty('message', 'OTP sent to your email');

      // Verify OTP was set in database
      const user = await User.findOne({ email: 'test@example.com' }).select('+otp +otpExpires');
      expect(user).toHaveProperty('otp');
      expect(user).toHaveProperty('otpExpires');
    });

    it('should return 401 for invalid credentials', async () => {
      const loginData = {
        identifier: 'testuser',
        password: 'wrongpassword'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should return 401 for non-existent user', async () => {
      const loginData = {
        identifier: 'nonexistent',
        password: 'password123'
      };

      const response = await request(app)
        .post('/auth/login')
        .send(loginData)
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should return 400 for missing fields', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({ identifier: 'testuser' })
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Identifier and password are required');
    });
  });

  describe('POST /verify-otp', () => {
    let otp;

    beforeEach(async () => {
      // Create a test user and simulate login to get OTP
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };
      await User.create(userData);

      // Simulate login to set OTP
      const loginData = {
        identifier: 'testuser',
        password: 'password123'
      };
      await request(app)
        .post('/auth/login')
        .send(loginData);

      // Get the OTP from database
      const user = await User.findOne({ username: 'testuser' });
      otp = user.otp;
    });

    it('should verify OTP successfully', async () => {
      const verifyData = {
        identifier: 'testuser',
        otp: otp
      };

      const response = await request(app)
        .post('/auth/verify-otp')
        .send(verifyData)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('username', 'testuser');
      expect(response.body.user).toHaveProperty('email', 'test@example.com');

      // Verify OTP was cleared
      const user = await User.findOne({ username: 'testuser' }).select('+otp +otpExpires');
      expect(user.otp).toBeNull();
      expect(user.otpExpires).toBeNull();
    });

    it('should return 401 for invalid OTP', async () => {
      const verifyData = {
        identifier: 'testuser',
        otp: '123456'
      };

      const response = await request(app)
        .post('/auth/verify-otp')
        .send(verifyData)
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid or expired OTP');
    });

    it('should return 401 for expired OTP', async () => {
      // Expire the OTP
      const user = await User.findOne({ username: 'testuser' }).select('+otp +otpExpires');
      user.otpExpires = new Date(Date.now() - 1000); // Set to past
      await user.save();

      const verifyData = {
        identifier: 'testuser',
        otp: otp
      };

      const response = await request(app)
        .post('/auth/verify-otp')
        .send(verifyData)
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid or expired OTP');
    });

    it('should return 400 for missing fields', async () => {
      const response = await request(app)
        .post('/auth/verify-otp')
        .send({ identifier: 'testuser' })
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Identifier and OTP are required');
    });
  });
});
