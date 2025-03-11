// server.js
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET_KEY = process.env.JWT_SECRET;

const OTP_EXPIRY = 10 * 60 * 1000; // 10 minutes in milliseconds

// Разрешаем CORS для вашего фронтенда
app.use(cors({
  origin: 'http://localhost:4321',  // Разрешаем доступ только с этого домена
  credentials: true  // Разрешаем отправку cookies
}));

app.use(express.json());
app.use(cookieParser());

// Эндпоит для генерации токена и сохранения в cookie
app.post('/generate-token', (req, res) => {
  const payload = { user: '+48690483990' }; // Пример payload
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

  // Сохраняем токен в cookie
  res.cookie('auth_token', token, { 
    httpOnly: true, 
    secure: true,  
    sameSite: 'None', 
    maxAge: 3600000
  }); // secure: false для HTTP
  res.json({ message: 'Token generated and stored in cookie', payload });
});

// Middleware для проверки токена
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
    req.user = decoded; // Сохраняем данные пользователя в запрос
    next();
  });
};

// Эндпоит для проверки токена
app.get('/check-token', verifyToken, (req, res) => {
  res.json({ message: 'Token is valid', user: req.user });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
