const request = require('supertest');
const app = require('../app');
const User = require('../models/User');

describe('Authentication Integration Tests', () => {
  describe('POST /register', () => {
    it('should register a new user successfully', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/register')
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
        .post('/register')
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
        .post('/register')
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
        .post('/register')
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
        .post('/register')
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

    it('should login successfully with username', async () => {
      const loginData = {
        identifier: 'testuser',
        password: 'password123'
      };

      const response = await request(app)
        .post('/login')
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('id');
      expect(response.body.user).toHaveProperty('username', 'testuser');
      expect(response.body.user).toHaveProperty('email', 'test@example.com');
    });

    it('should login successfully with email', async () => {
      const loginData = {
        identifier: 'test@example.com',
        password: 'password123'
      };

      const response = await request(app)
        .post('/login')
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('user');
      expect(response.body.user).toHaveProperty('username', 'testuser');
      expect(response.body.user).toHaveProperty('email', 'test@example.com');
    });

    it('should return 401 for invalid credentials', async () => {
      const loginData = {
        identifier: 'testuser',
        password: 'wrongpassword'
      };

      const response = await request(app)
        .post('/login')
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
        .post('/login')
        .send(loginData)
        .expect(401);

      expect(response.body).toHaveProperty('error', 'Invalid credentials');
    });

    it('should return 400 for missing fields', async () => {
      const response = await request(app)
        .post('/login')
        .send({ identifier: 'testuser' })
        .expect(400);

      expect(response.body).toHaveProperty('error', 'Identifier and password are required');
    });
  });
});
