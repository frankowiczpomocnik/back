// server.js
const express = require('express');
const { createClient } = require("@sanity/client");
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require("helmet");
const multer = require("multer");
const twilio = require("twilio");
const rateLimit = require("express-rate-limit");
const logger = require('pino')();
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY = process.env.JWT_SECRET;

const OTP_EXPIRY = 10 * 60 * 500; 


app.use(cors({
  origin: process.env.CORS_ORIGIN,  
  credentials: true,
  methods: ['GET', 'POST']
}));

app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', apiLimiter);

// OTP specific rate limiting
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each IP to 5 OTP requests per hour
  message: { error: 'Too many OTP requests, please try again later.' }
});

// Sanity client
const sanity = createClient({
  projectId: process.env.SANITY_PROJECT_ID,
  dataset: process.env.SANITY_DATASET,
  useCdn: process.env.NODE_ENV === 'production',
  apiVersion: "2025-03-07",
  token: process.env.SANITY_TOKEN,
});

// Twilio client
const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

// File upload configuration
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { 
    fileSize: 5 * 1024 * 1024, // 5MB file size limit
    files: 10 
  },
  fileFilter: (req, file, cb) => {
    // Validate file types if needed
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf', 'application/msword'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only JPEG, PNG, PDF and DOC files are allowed.'));
    }
  }
});

// Validation functions
const validatePhone = (phone) => {
  const phoneRegex = /^\+?\d{7,15}$/;
  return phoneRegex.test(phone);
};

const validateRequest = (req, res, requiredFields) => {
  for (const field of requiredFields) {
    if (!req.body[field]) {
      res.status(400).json({ error: `${field} is required` });
      return false;
    }
  }
  
  if (req.body.phone && !validatePhone(req.body.phone)) {
    res.status(400).json({ error: "Invalid phone number format" });
    return false;
  }
  
  return true;
};


app.post('/generate-token', (req, res) => {
  const payload = { user: '+48690483990' }; 
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });


  res.cookie('auth_token', token, { 
    httpOnly: true,   
    secure: true,  
    sameSite: 'None', 
    maxAge: 3600000
  }); 
  res.json({ message: 'Token generated and stored in cookie', payload });
});


const verifyToken = (req, res, next) => {
  const token = req.cookies.auth_token;
  console.log(token);
  if (!token) {
    return res.status(403).json({ error: 'Token not found' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token is invalid' });
    }
    req.user = decoded; 
    next();
  });
};


app.get('/check-token', verifyToken, (req, res) => {
  res.json({ message: 'Token is valid', user: req.user });
});


// Global error handler
app.use((err, req, res, next) => {
  logger.error(err);
  
  if (NODE_ENV === 'development') {
    return res.status(500).json({ error: err.message, stack: err.stack });
  }
  
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});


// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    // Close any other resources or connections here
  });
}); 