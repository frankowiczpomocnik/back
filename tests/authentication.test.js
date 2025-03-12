// tests/authentication.test.js
const request = require('supertest');
const jwt = require('jsonwebtoken');
const sinon = require('sinon');
const app = require('../server'); // Make sure to export app from server.js
const { createClient } = require('@sanity/client');
const twilio = require('twilio');

// Mock external dependencies
jest.mock('@sanity/client');
jest.mock('twilio');

describe('Authentication & OTP Tests', () => {
  let mockSanityClient;
  let mockTwilioClient;
  
  beforeEach(() => {
    // Reset all mocks before each test
    jest.clearAllMocks();
    
    // Setup mock Sanity client
    mockSanityClient = {
      fetch: jest.fn(),
      create: jest.fn(),
      delete: jest.fn()
    };
    createClient.mockReturnValue(mockSanityClient);
    
    // Setup mock Twilio client
    mockTwilioClient = {
      messages: {
        create: jest.fn().mockResolvedValue({ sid: 'test-sid' })
      }
    };
    twilio.mockReturnValue(mockTwilioClient);
  });
  
  afterAll(() => {
    jest.restoreAllMocks();
  });

  describe('Token Verification Middleware', () => {
    test('should return 403 if no token is provided', async () => {
      const response = await request(app)
        .get('/check-token');
      
      expect(response.statusCode).toBe(403);
      expect(response.body).toHaveProperty('error', 'Token not found');
    });
    
    test('should return 403 if token is invalid', async () => {
      const response = await request(app)
        .get('/check-token')
        .set('Cookie', ['auth_token=invalid-token']);
      
      expect(response.statusCode).toBe(403);
      expect(response.body).toHaveProperty('error', 'Token is invalid');
    });
    
    test('should pass if token is valid', async () => {
      // Create a valid token
      const token = jwt.sign({ phone: '+123456789' }, process.env.JWT_SECRET);
      
      const response = await request(app)
        .get('/check-token')
        .set('Cookie', [`auth_token=${token}`]);
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('message', 'Token is valid');
      expect(response.body.user).toHaveProperty('phone', '+123456789');
    });
  });

  describe('OTP Generation and Validation', () => {
    test('should fail if phone number is missing', async () => {
      const response = await request(app)
        .post('/api/send-otp')
        .send({});
      
      expect(response.statusCode).toBe(400);
      expect(response.body).toHaveProperty('error', 'phone is required');
    });
    
    test('should fail if phone number is invalid', async () => {
      const response = await request(app)
        .post('/api/send-otp')
        .send({ phone: 'invalid-phone' });
      
      expect(response.statusCode).toBe(400);
      expect(response.body).toHaveProperty('error', 'Invalid phone number format');
    });
    
    test('should generate and store OTP in Sanity', async () => {
      const phone = '+123456789';
      
      // Mock Sanity responses
      mockSanityClient.fetch.mockResolvedValueOnce(null); // No existing OTP
      mockSanityClient.create.mockResolvedValueOnce({ _id: 'new-otp-id' });
      mockSanityClient.fetch.mockResolvedValueOnce({ _id: 'new-otp-id', otp: '1234' }); // Verify OTP was created
      
      const response = await request(app)
        .post('/api/send-otp')
        .send({ phone });
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('message', 'OTP sent successfully');
      expect(response.body).toHaveProperty('phone', phone);
      
      // Verify Sanity interactions
      expect(mockSanityClient.fetch).toHaveBeenCalledTimes(2);
      expect(mockSanityClient.create).toHaveBeenCalledTimes(1);
      
      // Verify the OTP document structure
      const createCallArg = mockSanityClient.create.mock.calls[0][0];
      expect(createCallArg).toHaveProperty('_type', 'otp');
      expect(createCallArg).toHaveProperty('phone', phone);
      expect(createCallArg.otp).toMatch(/^\d{4}$/); // 4-digit OTP
      
      // Verify Twilio interaction
      expect(mockTwilioClient.messages.create).toHaveBeenCalledTimes(1);
      const twilioCallArg = mockTwilioClient.messages.create.mock.calls[0][0];
      expect(twilioCallArg.to).toBe(phone);
      expect(twilioCallArg.body).toContain(createCallArg.otp);
    });
    
    test('should delete existing OTP before creating a new one', async () => {
      const phone = '+123456789';
      const existingOtp = { _id: 'existing-otp-id', otp: '5678', phone };
      
      // Mock Sanity responses
      mockSanityClient.fetch.mockResolvedValueOnce(existingOtp); // Existing OTP found
      mockSanityClient.create.mockResolvedValueOnce({ _id: 'new-otp-id' });
      mockSanityClient.fetch.mockResolvedValueOnce({ _id: 'new-otp-id', otp: '1234' }); // Verify OTP was created
      
      const response = await request(app)
        .post('/api/send-otp')
        .send({ phone });
      
      expect(response.statusCode).toBe(200);
      
      // Verify delete was called for existing OTP
      expect(mockSanityClient.delete).toHaveBeenCalledWith('existing-otp-id');
      
      // Verify new OTP was created
      expect(mockSanityClient.create).toHaveBeenCalledTimes(1);
    });
    
    test('should not send SMS if OTP creation in Sanity fails', async () => {
      const phone = '+123456789';
      
      // Mock Sanity responses
      mockSanityClient.fetch.mockResolvedValueOnce(null); // No existing OTP
      mockSanityClient.create.mockResolvedValueOnce({ _id: 'new-otp-id' });
      mockSanityClient.fetch.mockResolvedValueOnce(null); // OTP verification fails
      
      // This should throw an error because OTP verification failed
      const response = await request(app)
        .post('/api/send-otp')
        .send({ phone });
      
      expect(response.statusCode).toBe(500);
      
      // Verify Twilio was not called
      expect(mockTwilioClient.messages.create).not.toHaveBeenCalled();
    });
  });

  describe('OTP Validation', () => {
    test('should fail if OTP is missing', async () => {
      const response = await request(app)
        .post('/api/validate-otp')
        .send({ phone: '+123456789' });
      
      expect(response.statusCode).toBe(400);
      expect(response.body).toHaveProperty('error', 'otp is required');
    });
    
    test('should fail if OTP is incorrect', async () => {
      const phone = '+123456789';
      const otp = '1234';
      
      // Mock Sanity response for non-matching OTP
      mockSanityClient.fetch.mockResolvedValueOnce({ _id: 'otp-id', otp: '5678' });
      
      const response = await request(app)
        .post('/api/validate-otp')
        .send({ phone, otp });
      
      expect(response.statusCode).toBe(400);
      expect(response.body).toHaveProperty('error', 'Invalid OTP');
      
      // Verify OTP was not deleted
      expect(mockSanityClient.delete).not.toHaveBeenCalled();
    });
    
    test('should succeed if OTP is correct', async () => {
      const phone = '+123456789';
      const otp = '1234';
      const otpRecord = { _id: 'otp-id', otp, phone };
      
      // Mock Sanity response for matching OTP
      mockSanityClient.fetch.mockResolvedValueOnce(otpRecord);
      
      const response = await request(app)
        .post('/api/validate-otp')
        .send({ phone, otp });
      
      expect(response.statusCode).toBe(200);
      expect(response.body).toHaveProperty('message', '✅ OTP verified successfully!');
      
      // Verify OTP was deleted
      expect(mockSanityClient.delete).toHaveBeenCalledWith(otpRecord._id);
      
      // Verify JWT cookie was set
      expect(response.headers['set-cookie']).toBeDefined();
      const cookieHeader = response.headers['set-cookie'][0];
      expect(cookieHeader).toContain('auth_token=');
      expect(cookieHeader).toContain('HttpOnly');
      expect(cookieHeader).toContain('Secure');
    });
    
    test('should fail if OTP record does not exist', async () => {
      const phone = '+123456789';
      const otp = '1234';
      
      // Mock Sanity response for no OTP record
      mockSanityClient.fetch.mockResolvedValueOnce(null);
      
      const response = await request(app)
        .post('/api/validate-otp')
        .send({ phone, otp });
      
      expect(response.statusCode).toBe(400);
      expect(response.body).toHaveProperty('error', 'Invalid OTP');
    });
  });
});