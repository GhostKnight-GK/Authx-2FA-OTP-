const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const admin = require('firebase-admin');
const serviceAccount = require('./firebaseConfig.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('AuthX Server Running ✅');
});

// Register API
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const userRef = db.collection('users').doc(email);
    const doc = await userRef.get();
    if (doc.exists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await userRef.set({
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    });

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login API with OTP generation
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const userRef = db.collection('users').doc(email);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(400).json({ message: 'User not found' });
    }

    const user = doc.data();
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60000); // 5 minutes

    await db.collection('otps').doc(email).set({
      otp,
      expiresAt: expiresAt.toISOString(),
    });

    // Simulate OTP sending
    console.log(`OTP for ${email}: ${otp} (valid till ${expiresAt.toISOString()})`);

    res.status(200).json({ message: 'Login successful, OTP sent (simulated)' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ✅ OTP Verification API
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }

    const otpRef = db.collection('otps').doc(email);
    const doc = await otpRef.get();

    if (!doc.exists) {
      return res.status(400).json({ message: 'OTP not found. Please login again.' });
    }

    const data = doc.data();
    const currentTime = new Date();
    const expiresAt = new Date(data.expiresAt);

    if (currentTime > expiresAt) {
      return res.status(400).json({ message: 'OTP has expired. Please login again.' });
    }

    if (data.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // OTP is valid (Session/token generation can be added here in Phase 5+)
    return res.status(200).json({ message: 'OTP verified. Login successful ✅' });
  } catch (error) {
    console.error('OTP verification error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Test Email Route (Ethereal)
app.get('/test-email', async (req, res) => {
  try {
    const testAccount = await nodemailer.createTestAccount();

    const transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });

    let info = await transporter.sendMail({
      from: '"AuthX 👻" <authx@example.com>',
      to: 'test@example.com',
      subject: 'Hello from AuthX',
      text: 'This is a test email sent from AuthX backend!',
    });

    console.log('Message sent: %s', info.messageId);
    console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));

    res.json({
      message: 'Test email sent! Check console for preview URL.',
      previewURL: nodemailer.getTestMessageUrl(info),
    });
  } catch (error) {
    console.error('Error sending test email:', error);
    res.status(500).json({ message: 'Failed to send test email' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
