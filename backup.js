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
const crypto = require('crypto');
const logger = require('pino')();
require("dotenv").config();
const { Redis } = require('@upstash/redis');

// Upstash Redis
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const MAX_RETRIES = 3;
const RETRY_DELAY = 1000;

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
  windowMs: 24 * 60 * 60 * 1000, // 24 часа (сутки)
  max: 5, // лимит каждого IP до 5 OTP запросов в сутки
  message: { error: 'Dzienny limit 5 żądań  został przekroczony. Spróbuj ponownie jutro.' }
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

// Функция загрузки файла с повторными попытками
async function uploadFileWithRetries(file, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`Uploading file: ${file.originalname}, Attempt: ${attempt}/${retries}`);
      const asset = await sanity.assets.upload("file", file.buffer, { filename: file.originalname });

      console.log(`✅ Success: ${file.originalname} uploaded as ${asset._id}`);
      return {
        _key: crypto.randomUUID(),
        _type: "file",
        asset: { _type: "reference", _ref: asset._id }
      };
    } catch (error) {
      console.error(`❌ Error uploading ${file.originalname}:`, error.message);

      if (attempt < retries) {
        console.log(`Retrying in ${RETRY_DELAY}ms...`);
        await new Promise(res => setTimeout(res, RETRY_DELAY));
      } else {
        console.error(`❌ Failed to upload ${file.originalname} after ${retries} attempts`);
      }
    }
  }
  return null; // Если не удалось загрузить файл
}

// Функция создания документа с повторными попытками
async function createDocumentWithRetries(doc, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`📄 Creating document, attempt ${attempt}/${retries}`);
      const result = await sanity.create(doc);
      console.log(`✅ Document created with ID: ${result._id}`);
      return result;
    } catch (error) {
      console.error(`❌ Error creating document: ${error.message}`);

      if (error.message.includes("already exists")) {
        console.warn("⚠️ Document already exists, skipping creation.");
        return null;
      }

      if (attempt < retries) {
        console.log(`Retrying in ${RETRY_DELAY}ms...`);
        await new Promise(res => setTimeout(res, RETRY_DELAY));
      } else {
        console.error("❌ Failed to create document after multiple attempts.");
        throw error; // Прокидываем ошибку дальше
      }
    }
  }
}

// Routes
app.get("/api/ping", (req, res) => {
  res.json({ message: "Server is running! 🚀" });
});

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



// async function waitForOtpRecord(phone, retries = 3, delay = 1000) {
//   for (let i = 0; i < retries; i++) {
//     const otpRecord = await redis.get(`otp:${phone}`);
//     if (otpRecord) return otpRecord;
    
//     console.log(`Retrying fetch OTP (${i + 1}/${retries})...`);
//     await new Promise(res => setTimeout(res, delay));
//   }
//   return null;
// }

const retry = async (fn, retries = 3, delay = 1000) => {
  try {
    return await fn();
  } catch (error) {
    if (retries <= 0) throw error;
    await new Promise(resolve => setTimeout(resolve, delay));
    return retry(fn, retries - 1, delay * 2); // Exponential backoff
  }
};

app.get('/check-token', verifyToken, (req, res) => {
  res.json({ message: 'Token is valid', user: req.user });
});

// Обновленная функция waitForOtpRecord, которая просто возвращает то, что нашла в Redis
async function waitForOtpRecord(phone, retries = 3, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    const otpRecord = await redis.get(`otp:${phone}`);
    if (otpRecord) return otpRecord;
    
    console.log(`Retrying fetch OTP (${i + 1}/${retries})...`);
    await new Promise(res => setTimeout(res, delay));
  }
  return null;
}

// app.post("/api/send-otp", otpLimiter, async (req, res, next) => {
//   try {
//     if (!validateRequest(req, res, ['phone'])) return;

//     const { phone } = req.body;
//     const otp = Math.floor(1000 + Math.random() * 9000).toString();
//     const otpKey = `otp:${phone}`;

//     console.log(`🔵 Checking existing OTP for ${phone} in Redis`);
//     const existingOtp = await waitForOtpRecord(phone);
//     if (existingOtp) {
//       console.log(`⚠️ OTP already exists for ${phone}, request denied.`);
//       return res.status(400).json({ error: "OTP already sent. Please wait before requesting a new one." });
//     }

//     console.log(`🟢 Storing OTP for ${phone} in Redis: ${otp}`);
//     await redis.set(otpKey, otp, { ex: OTP_EXPIRY / 1000 });

//     const testOtp = await waitForOtpRecord(phone);
//     console.log(`✅ Redis now contains OTP: ${testOtp}`);

//     console.log(`📨 Sending OTP to ${phone} via Twilio`);
    
//     // Пример функции retry для асинхронных операций


// // Пример применения
// await retry(() => twilioClient.messages.create({
//   body: `Twój kod weryfikacyjny to: ${otp}`,
//   from: process.env.TWILIO_PHONE,
//   to: req.body.phone
// }));

//     res.status(200).json({ message: "OTP sent successfully", phone });
//   } catch (error) {
//     console.error("❌ Error in send-otp: ", error);
//     next(error);
//   }
// });

// Updated function to send OTP
app.post("/api/send-otp", otpLimiter, async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone'])) return;

    const { phone } = req.body;
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const otpKey = `otp:${phone}`;
    const sequenceKey = `otp_sequence:${phone}`;
    
    // Check for existing OTP
    console.log(`🔵 Checking existing OTP for ${phone} in Redis`);
    const existingOtp = await redis.get(otpKey);
    
    // Delete existing OTP if found
    if (existingOtp) {
      console.log(`⚠️ Found existing OTP for ${phone}, deleting it to create a new one.`);
      await redis.del(otpKey);
    }
    
    // Get next sequence number
    let sequence = 1;
    const existingSequence = await redis.get(sequenceKey);
    if (existingSequence) {
      sequence = parseInt(existingSequence) + 1;
    }
    
    // Save new sequence
    await redis.set(sequenceKey, sequence.toString(), { ex: 24 * 60 * 60 });
    
    // Store OTP as a simple string instead of JSON
    console.log(`🟢 Storing OTP for ${phone} in Redis: ${otp} (sequence: ${sequence})`);
    await redis.set(otpKey, otp, { ex: OTP_EXPIRY / 1000 });

    // Store sequence separately
    await redis.set(`${otpKey}:sequence`, sequence.toString(), { ex: OTP_EXPIRY / 1000 });

    const testOtp = await redis.get(otpKey);
    console.log(`✅ Redis now contains OTP: ${testOtp}`);

    console.log(`📨 Sending OTP to ${phone} via Twilio with sequence ${sequence}`);
    
    // Send SMS with sequence number
    await retry(() => twilioClient.messages.create({
      body: `Twój kod N ${sequence} weryfikacyjny to: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: req.body.phone
    }));

    res.status(200).json({ message: "OTP sent successfully", phone });
  } catch (error) {
    console.error("❌ Error in send-otp: ", error);
    next(error);
  }
});

// app.post("/api/validate-otp", apiLimiter, async (req, res, next) => {
//   try {
//     if (!validateRequest(req, res, ['phone', 'otp'])) return;

//     const { phone, otp } = req.body;
//     const otpKey = `otp:${phone}`;

//     console.log(`🔵 Fetching stored OTP for ${phone} from Redis`);
//     const storedOtp = await waitForOtpRecord(phone);
//     console.log(`Stored OTP (${typeof storedOtp}): ${storedOtp}, Entered OTP (${typeof otp}): ${otp}`);
    
//     if (!storedOtp) {
//       console.log(`❌ No OTP found for ${phone} or it has expired.`);
//       return res.status(400).json({ error: "Invalid or expired OTP" });
//     }

//     if (storedOtp.toString().trim() !== otp.toString().trim()) {
//       console.log(`❌ Incorrect OTP entered for ${phone}`);
//       return res.status(400).json({ error: "Incorrect OTP" });
//     }

//     console.log(`✅ OTP verified successfully for ${phone}, deleting from Redis`);
//     await redis.del(otpKey);

//     const token = jwt.sign({ phone }, SECRET_KEY, { expiresIn: "1h" });

//     console.log(`🔑 Generating JWT token for ${phone}`);
//     res.cookie("auth_token", token, {
//       httpOnly: true,
//       secure: true,
//       sameSite: 'None',
//       maxAge: 60 * 60 * 1000
//     });

//     res.status(200).json({ message: "✅ OTP verified successfully!" });
//   } catch (error) {
//     console.error("❌ Error in validate-otp: ", error);
//     next(error);
//   }
// });

// Updated function to validate OTP
app.post("/api/validate-otp", apiLimiter, async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone', 'otp'])) return;
    
    const { phone, otp } = req.body;
    const otpKey = `otp:${phone}`;
    
    console.log(`🔵 Fetching stored OTP for ${phone} from Redis`);
    const storedOtp = await redis.get(otpKey);
    
    if (!storedOtp) {
      console.log(`❌ No OTP found for ${phone} or it has expired.`);
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }
    
    // Get sequence for logging purposes
    const sequence = await redis.get(`${otpKey}:sequence`) || "unknown";
    console.log(`📊 Found OTP: ${storedOtp} (sequence: ${sequence})`);
    
    // Simple string comparison
    const enteredOtp = String(otp).trim();
    const storedOtpStr = String(storedOtp).trim();
    
    console.log(`Compare - Stored OTP: "${storedOtpStr}" (${typeof storedOtpStr}), Entered OTP: "${enteredOtp}" (${typeof enteredOtp})`);
    
    if (storedOtpStr !== enteredOtp) {
      console.log(`❌ Incorrect OTP entered for ${phone}`);
      return res.status(400).json({ error: "Incorrect OTP" });
    }
    
    console.log(`✅ OTP verified successfully for ${phone}, deleting from Redis`);
    await redis.del(otpKey);
    await redis.del(`${otpKey}:sequence`);
    
    // Generate JWT token
    const token = jwt.sign({ phone }, SECRET_KEY, { expiresIn: "1h" });
    
    console.log(`🔑 Generating JWT token for ${phone}`);
    res.cookie("auth_token", token, {
      httpOnly: true,
      secure: true,
      sameSite: 'None',
      maxAge: 60 * 60 * 1000
    });
    
    res.status(200).json({ message: "✅ OTP verified successfully!" });
  } catch (error) {
    console.error("❌ Error in validate-otp: ", error);
    next(error);
  }
});





app.post("/api/files", verifyToken, upload.array("files", 10), async (req, res, next) => {
  try {
    const { phone } = req.user;
    const { name, description } = req.body;
    console.log(`📂 description ${description} `);
    if (!name) {
      return res.status(400).json({ error: "name is required" });
    }

    if (description && description.length > 500) {
      return res.status(400).json({ error: "description must be 500 characters or less" });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    console.log(`📂 Uploading ${req.files.length} files for user: ${phone}`);

    // Upload files with retries
    const fileUploads = await Promise.all(req.files.map(file => uploadFileWithRetries(file)));

    // Filter out failed uploads
    const successfulUploads = fileUploads.filter(file => file !== null);

    if (successfulUploads.length === 0) {
      return res.status(500).json({ error: "All file uploads failed" });
    }

    // Create document in Sanity
    const doc = {
      _type: "files",
      name,
      phone,
      description: description || "", // Ensure description is always included
      files: successfulUploads,
      createdAt: new Date().toISOString()
    };

    const result = await createDocumentWithRetries(doc);

    res.clearCookie("auth_token", {
      httpOnly: true,
      secure: true,
      sameSite: "None"
    });

    res.status(201).json({ message: "Files uploaded successfully", data: result });
  } catch (error) {
    next(error);
  }
});

app.post("/api/links", verifyToken, async (req, res, next) => {
  try {
    const { phone } = req.user;
    const { name, link, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: "name is required" });
    }

    if (!link) {
      return res.status(400).json({ error: "link is required" });
    }

    if (description && description.length > 500) {
      return res.status(400).json({ error: "description must be 500 characters or less" });
    }

    // URL validation
    try {
      new URL(link);
    } catch (e) {
      return res.status(400).json({ error: "Invalid URL format" });
    }

    // Create document in Sanity
    const doc = {
      _type: "link",
      name,
      phone,
      link,
      description: description || "", // Ensure description is always included
      createdAt: new Date().toISOString()
    };

    const result = await createDocumentWithRetries(doc);

    res.clearCookie("auth_token", {
      httpOnly: true,
      secure: true,
      sameSite: "None"
    });

    res.status(201).json({ message: "Link added successfully", data: result });
  } catch (error) {
    next(error);
  }
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

module.exports = app;