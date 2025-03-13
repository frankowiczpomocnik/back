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

async function waitForOtpRecord(phone, retries = 3, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    const query = `*[_type == "otp" && phone == $phone][0]`;
    const otpRecord = await sanity.fetch(query, { phone, _ts: Date.now()  });

    if (otpRecord) return otpRecord;

    console.log(`Retrying fetch OTP (${i + 1}/${retries})...`);
    await new Promise(res => setTimeout(res, delay));
  }
  return null;
}


app.get('/check-token', verifyToken, (req, res) => {
  res.json({ message: 'Token is valid', user: req.user });
});

// app.post("/api/send-otp", otpLimiter, async (req, res, next) => {
//   try {
//     if (!validateRequest(req, res, ['phone'])) return;

//     // Generate 4-digit OTP
//     const otp = Math.floor(1000 + Math.random() * 9000).toString();

//     // First check if an OTP already exists and delete it
//     const existingQuery = `*[_type == "otp" && phone == $phone][0]`;
//     const existingOtp = await sanity.fetch(existingQuery, { phone: req.body.phone });

//     if (existingOtp) {
//       await sanity.delete(existingOtp._id);
//     }

//     // Create OTP document in Sanity
//     const doc = {
//       _type: "otp",
//       otp,
//       phone: req.body.phone,
//     };

//     // First create the OTP in Sanity
//     const result = await sanity.create(doc);

//     // Verify the OTP was created successfully
//     const createdOtp = await sanity.fetch(`*[_id == $id][0]`, { id: result._id });

//     if (!createdOtp) {
//       throw new Error("Failed to create OTP");
//     }

//     // Only now send the SMS since we've confirmed the OTP exists in Sanity
//     await twilioClient.messages.create({
//       body: `Your verification code is: ${otp}`,
//       from: process.env.TWILIO_PHONE,
//       to: req.body.phone
//     });

//     // Schedule OTP deletion
//     setTimeout(async () => {
//       try {
//         const stillExists = await sanity.fetch(`*[_id == $id][0]._id`, { id: result._id });
//         if (stillExists) {
//           await sanity.delete(result._id);
//           console.log(`OTP for ${req.body.phone} deleted from Sanity.`);
//         }
//       } catch (error) {
//         console.error("Failed to delete OTP:", error.message);
//       }
//     }, OTP_EXPIRY);

//     res.status(200).json({ message: "OTP sent successfully", phone: req.body.phone });
//   } catch (error) {
//     next(error);
//   }
// });

// app.post("/api/validate-otp", apiLimiter, async (req, res, next) => {
//   try {
//     if (!validateRequest(req, res, ['phone', 'otp'])) return;

//     const { phone, otp } = req.body;

//     // Find OTP record in Sanity
//     const otpRecord = await waitForOtpRecord(phone);
//     if (!otpRecord) {
//       return res.status(400).json({ error: "Invalid OTP (not found)" });
//     }
//     // Validate OTP
//     if (!otpRecord) {
//       return res.status(400).json({ error: "Invalid OTP !otpRecord " });
//     }

//     if (otpRecord.otp !== otp) {
//       return res.status(400).json({ error: `otpRecord.otp !== otp` });
//     }

//     // Delete OTP after successful verification
//     await sanity.delete(otpRecord._id);

//     // Generate JWT token
//     const token = jwt.sign({ phone }, SECRET_KEY, { expiresIn: "1h" });

//     // Set secure cookie
//     res.cookie("auth_token", token, {
//       httpOnly: true,
//       secure: true,
//       sameSite: 'None',
//       maxAge: 60 * 60 * 1000
//     });

//     res.status(200).json({ message: "✅ OTP verified successfully!" });
//   } catch (error) {
//     next(error); // Pass to the global error handler
//   }
// });

app.post("/api/send-otp", otpLimiter, async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone'])) return;

    const { phone } = req.body;
    const otp = Math.floor(1000 + Math.random() * 9000).toString();
    const otpKey = `otp:${phone}`;

    console.log(`🔵 Checking existing OTP for ${phone} in Redis`);
    const existingOtp = await redis.get(otpKey);
    if (existingOtp) {
      console.log(`⚠️ OTP already exists for ${phone}, request denied.`);
      return res.status(400).json({ error: "OTP already sent. Please wait before requesting a new one." });
    }

    console.log(`🟢 Storing OTP for ${phone} in Redis: ${otp}`);
    await redis.set(otpKey, otp, { ex: OTP_EXPIRY / 1000 });

    const testOtp = await redis.get(otpKey);
    console.log(`✅ Redis now contains OTP: ${testOtp}`);

    console.log(`📨 Sending OTP to ${phone} via Twilio`);
    await twilioClient.messages.create({
      body: `Your verification code is: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: phone
    });

    res.status(200).json({ message: "OTP sent successfully", phone });
  } catch (error) {
    console.error("❌ Error in send-otp: ", error);
    next(error);
  }
});

app.post("/api/validate-otp", apiLimiter, async (req, res, next) => {
  try {
    if (!validateRequest(req, res, ['phone', 'otp'])) return;

    const { phone, otp } = req.body;
    const otpKey = `otp:${phone}`;

    console.log(`🔵 Fetching stored OTP for ${phone} from Redis`);
    const storedOtp = await redis.get(otpKey);
    console.log(`Stored OTP (${typeof storedOtp}): ${storedOtp}, Entered OTP (${typeof otp}): ${otp}`);
    
    if (!storedOtp) {
      console.log(`❌ No OTP found for ${phone} or it has expired.`);
      return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    if (storedOtp.toString().trim() !== otp.toString().trim()) {
      console.log(`❌ Incorrect OTP entered for ${phone}`);
      return res.status(400).json({ error: "Incorrect OTP" });
    }

    console.log(`✅ OTP verified successfully for ${phone}, deleting from Redis`);
    await redis.del(otpKey);

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

    if (!req.body.name) {
      return res.status(400).json({ error: "name is required" });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    console.log(`📂 Uploading ${req.files.length} files for user: ${phone}`);

    // Загружаем файлы с повторными попытками
    const fileUploads = await Promise.all(req.files.map(file => uploadFileWithRetries(file)));

    // Удаляем неудачные загрузки
    const successfulUploads = fileUploads.filter(file => file !== null);

    if (successfulUploads.length === 0) {
      return res.status(500).json({ error: "All file uploads failed" });
    }

    // Создаем документ в Sanity
    const doc = {
      _type: "files",
      name: req.body.name,
      phone,
      files: successfulUploads,
      createdAt: new Date().toISOString()
    };

    // Улучшенная функция создания документа
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
    // Получаем телефон из токена вместо body
    const { phone } = req.user;

    // Проверяем только name и link в теле запроса
    if (!req.body.name) {
      return res.status(400).json({ error: "name is required" });
    }

    if (!req.body.link) {
      return res.status(400).json({ error: "link is required" });
    }

    // URL validation
    try {
      new URL(req.body.link);
    } catch (e) {
      return res.status(400).json({ error: "Invalid URL format" });
    }

    // Create document in Sanity
    const doc = {
      _type: "link",
      name: req.body.name,
      phone, // Используем телефон из токена
      link: req.body.link,
      createdAt: new Date().toISOString()
    };

    // Улучшенная функция создания документа
    const result = await createDocumentWithRetries(doc);

    // Clear cookie before sending response
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