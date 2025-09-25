const express = require('express');
const multer = require('multer');
const path = require('path');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config({path: 'config.env'});
const fs = require('fs');
const { spawn } = require('child_process');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const rateLimit = require('express-rate-limit');
const app = express();
const port = 3000;

// Import models
const File = require('./models/File');
const AnalysisReport = require('./models/AnalysisReport');
const User = require('./models/User');
const Complaint = require('./models/Complaint');

// Import middleware
const auth = require('./middleware/auth');
const optionalAuth = require('./middleware/optionalAuth');

// Import helper functions
const sendToAIModel = require('./helpers/sendToAIModel'); // Sends file to AI model for analysis
const runPythonScript = require('./helpers/runPythonScript'); // Runs a Python script and returns JSON output
const isFileSizeSuitable = require('./helpers/isFileSizeSuitable'); // Checks if file size is suitable for AI analysis

app.use(cors());
app.use(express.json()); // For parsing JSON bodies

// JWT Secret from environment
const JWT_SECRET = process.env.JWT_SECRET;

mongoose.connect(process.env.DB_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

const upload = multer({ dest: 'uploads/', limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB

app.use('/plots', express.static('plots'));

// AI Model configuration
const AI_MODEL_URL = process.env.AI_MODEL_URL;
const AI_MODEL_HEADERS = {
  "Authorization": `Bearer ${process.env.AI_MODEL_TOKEN}`
};

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Session and Passport setup
app.use(session({
  secret: process.env.JWT_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user._id);
});
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.OAUTH_CALLBACK_BASE + '/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      // Try to find by email/username in case user already exists with another provider
      const email = profile.emails[0].value;
      user = await User.findOne({ $or: [{ email }, { username: email }] });
      if (user) {
        // Link Google ID to existing user
        user.googleId = profile.id;
        await user.save();
        return done(null, user);
      }
      // Otherwise, create new user
      user = await User.create({
        name: profile.displayName,
        email: email,
        username: email,
        googleId: profile.id,
        role: 'other'
      });
    }
    return done(null, user);
  } catch (err) {
    // Handle duplicate key error gracefully
    if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
      // Find the existing user by username/email
      const email = profile.emails[0].value;
      const user = await User.findOne({ $or: [{ email }, { username: email }] });
      if (user) return done(null, user);
    }
    return done(err, null);
  }
}));

// GitHub OAuth Strategy
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.OAUTH_CALLBACK_BASE + '/auth/github/callback',
  scope: ['user:email']
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let email = (profile.emails && profile.emails[0] && profile.emails[0].value) || `${profile.username}@github.com`;
    let user = await User.findOne({ githubId: profile.id });
    if (!user) {
      // Try to find by email/username in case user already exists with another provider
      user = await User.findOne({ $or: [{ email }, { username: email }] });
      if (user) {
        // Link GitHub ID to existing user
        user.githubId = profile.id;
        await user.save();
        return done(null, user);
      }
      // Otherwise, create new user
      user = await User.create({
        name: profile.displayName || profile.username,
        email: email,
        username: email,
        githubId: profile.id,
        role: 'other'
      });
    }
    return done(null, user);
  } catch (err) {
    // Handle duplicate key error gracefully
    if (err.code === 11000 && err.keyPattern && err.keyPattern.username) {
      // Find the existing user by username/email
      let email = (profile.emails && profile.emails[0] && profile.emails[0].value) || `${profile.username}@github.com`;
      const user = await User.findOne({ $or: [{ email }, { username: email }] });
      if (user) return done(null, user);
    }
    return done(err, null);
  }
}));

// Google OAuth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: 'https://anonymous-frontend-l5z5.vercel.app/' }), (req, res) => {
  // Issue JWT and redirect to frontend with token
  const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
  res.redirect(`https://anonymous-frontend-l5z5.vercel.app/?token=${token}`);
});

// GitHub OAuth routes
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: 'https://anonymous-frontend-l5z5.vercel.app/' }), (req, res) => {
  // Issue JWT and redirect to frontend with token
  const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
  res.redirect(`https://anonymous-frontend-l5z5.vercel.app/?token=${token}`);
});

// Rate limiting for complaints endpoint
const complaintsRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // limit each IP to 5 complaints per hour
  message: {
    error: 'Too many complaints submitted from this IP, please try again after an hour.'
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Apply rate limiting to complaints endpoint
app.use('/complaints', complaintsRateLimit);

// Backward compatibility for OAuth success (redirects to frontend)
app.get('/oauth-success', (req, res) => {
  const token = req.query.token;
  if (token) {
    res.redirect(`https://anonymous-frontend-l5z5.vercel.app/?token=${token}`);
  } else {
    res.redirect('https://anonymous-frontend-l5z5.vercel.app/');
  }
});

// Authentication Routes
app.post('/signup', async (req, res) => {
  try {
    const { name, email, phone, jobTitle, yearsOfExperience, password, company } = req.body;

    // Validate required fields
    if (!name || !email || !phone || !jobTitle || !yearsOfExperience || !password || !company) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username: email }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const user = new User({
      name,
      email,
      phone,
      jobTitle,
      yearsOfExperience,
      company,
      username: email, // Using email as username
      password: hashedPassword
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    // Return user data (without password) and token
    const userResponse = {
      _id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      jobTitle: user.jobTitle,
      yearsOfExperience: user.yearsOfExperience,
      company: user.company,
      role: user.role,
      createdAt: user.createdAt
    };

    res.status(201).json({
      message: 'User created successfully',
      user: userResponse,
      token
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    // Return user data (without password) and token
    const userResponse = {
      _id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      jobTitle: user.jobTitle,
      yearsOfExperience: user.yearsOfExperience,
      company: user.company,
      role: user.role,
      createdAt: user.createdAt
    };

    res.json({
      message: 'Login successful',
      user: userResponse,
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Enhanced profile endpoint with upload history and pagination
app.get('/profile', auth, async (req, res) => {
  try {
    const user = req.user;
    // Remove pagination: fetch all files for the user
    const files = await File.find({ userId: user._id })
      .sort({ uploadDate: -1 })
      .lean();
    // For each file, get the analysis report
    const fileIds = files.map(f => f._id);
    const reports = await AnalysisReport.find({ fileId: { $in: fileIds } }).lean();
    const reportMap = {};
    for (const r of reports) {
      reportMap[r.fileId.toString()] = r;
    }
    // Build history array
    const history = files.map(f => {
      const report = reportMap[f._id.toString()];
      return {
        name: f.name,
        status: f.status,
        uploadDate: f.uploadDate,
        family: report?.predictions_family || [],
        accuracy: report?.probability_family || [],
        report: report || null
      };
    });
    res.json({
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        jobTitle: user.jobTitle,
        yearsOfExperience: user.yearsOfExperience,
        company: user.company,
        role: user.role,
        createdAt: user.createdAt
      },
      history
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// New endpoint to serve plot images securely
app.get('/api/plots/:filename', (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'plots', filename);
  res.sendFile(filePath, err => {
    if (err) {
      res.status(404).send('Plot not found');
    }
  });
});

const PLOTS_BASE_URL = process.env.PLOTS_BASE_URL || process.env.OAUTH_CALLBACK_BASE.replace(/\/$/, '');

app.post('/upload', optionalAuth, upload.single('file'), async (req, res) => {
  if (!req.file) {
    console.log('No file uploaded');
    return res.status(400).send('No file uploaded.');
  }

  const filePath = req.file.path;
  const originalName = req.file.originalname;
  const password = req.body.password || '';

  // Use req.user if present, otherwise guest (0)
  let userId = req.user ? req.user._id : 0;
  console.log('--- Upload Start ---');
  console.log(`UserId: ${userId}`);
  console.log(`Original filename: ${originalName}`);
  console.log(`File path: ${filePath}`);
  try {
    const stats = fs.statSync(filePath);
    console.log(`File size: ${stats.size} bytes`);
  } catch (e) {
    console.log('Could not get file size:', e.message);
  }

  try {
    // Always call the analyzer with file, original name, and optional password
    const args = [filePath, originalName];
    if (password) args.push(password);
    // If archive, add --keep-extracted flag
    const isArchive = /\.(zip|rar|7z)$/i.test(originalName);
    if (isArchive) args.push('--keep-extracted');
    console.log('Running static analyzer Python script...');
    const analysisResult = await runPythonScript(filePath, originalName, password, isArchive);
    console.log('Static analyzer finished.');

    // Check for password error from analyzer
    if (analysisResult && analysisResult.error && analysisResult.error.trim() === 'password is wrong') {
      fs.unlink(filePath, () => {});
      console.log('Password error detected: password is wrong');
      return res.status(400).json({ error: 'password is wrong ' });
    }

    // For each sample, run get-hashes, check DB, and build response
    const results = [];
    const filesToCleanup = [];
    for (const sample of analysisResult.results) {
      const sampleFile = sample.filename;
      const samplePath = sample.file_path;
      if (samplePath && samplePath !== filePath) filesToCleanup.push(samplePath);
      let hashResult = null;
      let dbStatus = null;
      let dbReport = null;
      let aiResult = null;
      const plotLinks = (sample.plots || []).map(p => `${PLOTS_BASE_URL}/api/plots/${path.basename(p)}`);
      if (sample.analysis && sample.analysis.error) {
        console.log(`Sample ${sampleFile}: analysis error: ${sample.analysis.error}`);
        results.push({
          filename: sampleFile,
          analysis: sample.analysis,
          plots: plotLinks,
          hash: null,
          dbStatus: 'analysis_error',
          dbReport: null,
          aiResult: null,
          error: sample.analysis.error
        });
        continue;
      }
      console.log(`Processing sample: ${sampleFile}`);
      if (samplePath) {
        try {
          console.log('Running hash calculation Python script...');
          hashResult = await runPythonScript(samplePath);
          console.log('Hash calculation finished.');
          if (hashResult && hashResult.md5) {
            const existingFile = await File.findOne({ hash: hashResult.md5, userId: userId });
            if (existingFile) {
              dbStatus = 'already_uploaded_by_user';
              dbReport = await AnalysisReport.findOne({ fileId: existingFile._id });
              console.log('File already uploaded by this user. Skipping AI.');
            } else {
              console.log('New file for this user. Creating DB record.');
              const newFileDoc = await File.create({
                name: sampleFile,
                hash: hashResult.md5,
                status: 'analyzed',
                uploadDate: new Date(),
                userId: userId
              });
              if (isFileSizeSuitable(filePath)) {
                console.log('File size suitable. Sending to AI model...');
                try {
                  aiResult = await sendToAIModel(filePath);
                  console.log('AI model analysis finished.');
                  if (!aiResult.predictions_file) {
                    throw new Error('AI model did not return predictions_file');
                  }
                  dbReport = await AnalysisReport.create({
                    fileId: newFileDoc._id,
                    analysisDate: new Date(),
                    predictions_file: aiResult.predictions_file,
                    probability_file: aiResult.probability_file ?? null,
                    predictions_family: aiResult.predictions_family ?? [],
                    probability_family: aiResult.probability_family ?? []
                  });
                  dbStatus = 'ai_analyzed';
                  console.log('Analysis report saved to database.');
                } catch (aiError) {
                  console.log('AI model analysis failed.');
                  console.error(`Sample ${sampleFile}: AI Model Error:`, aiError);
                  dbStatus = 'ai_failed';
                }
              } else {
                dbStatus = 'size_unsuitable';
                console.log('File size not suitable for AI analysis. Skipping AI.');
              }
            }
          } else {
            dbStatus = 'hash_failed';
            console.log(`Sample ${sampleFile}: hash generation failed.`);
          }
        } catch (err) {
          dbStatus = 'hash_error';
          console.log(`Sample ${sampleFile}: error during hash generation:`, err);
        }
      } else {
        dbStatus = 'not_available';
        console.log(`Sample ${sampleFile}: sample path not available.`);
      }
      results.push({
        filename: sampleFile,
        analysis: sample.analysis,
        plots: plotLinks,
        hash: hashResult,
        dbStatus,
        dbReport,
        aiResult
      });
      console.log(`Sample ${sampleFile}: dbStatus = ${dbStatus}`);
      console.log(`Sample ${sampleFile}: analysis result:`, JSON.stringify(sample.analysis));
    }
    res.json({ results });
    fs.unlink(filePath, () => {});
    for (const f of filesToCleanup) fs.unlink(f, () => {});
    console.log('--- Upload End ---');
  } catch (error) {
    console.error('Error processing file:', error);
    fs.unlink(filePath, () => {});
    console.log('--- Upload End (Error) ---');
    res.status(500).send(error.message);
  }
});

// Complaints endpoint with security validation
app.post('/complaints', async (req, res) => {
  try {
    console.log('--- Incoming complaint request ---');
    console.log('Request body:', req.body);
    
    // If user is authenticated, get userId from auth middleware
    let userId = null;
    let email = null;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      try {
        const token = req.headers.authorization.replace('Bearer ', '');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.userId;
        console.log('Authenticated userId:', userId);
      } catch (err) {
        console.log('JWT decode error:', err);
        // Invalid token, ignore and treat as guest
      }
    }
    
    // Accept email from body for guests
    if (req.body.email) {
      email = req.body.email;
      console.log('Guest email:', email);
    }
    
    const { message } = req.body;
    
    // SECURITY VALIDATION
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'Message is required and must be a string' });
    }
    
    if (message.length < 1 || message.length > 1000) {
      return res.status(400).json({ error: 'Message must be between 1 and 1000 characters' });
    }
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
      /javascript:/gi,
      /on\w+\s*=/gi,
      /<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi,
      /<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi,
      /<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(message)) {
        return res.status(400).json({ error: 'Message contains forbidden content' });
      }
    }
    
    // Sanitize the message (simple HTML encoding)
    const sanitizedMessage = message
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
    
    if (!userId && !email) {
      console.log('Missing message or user/email');
      return res.status(400).json({ error: 'Message and (user or email) are required.' });
    }
    
    const complaint = new Complaint({
      user: userId || undefined,
      email: email || undefined,
      message: sanitizedMessage  // Use sanitized message
    });
    
    await complaint.save();
    console.log('Complaint saved to DB:', complaint);

    // Send email to support (use sanitized message)
    const supportEmail = process.env.SUPPORT_EMAIL;
    let subject = 'New Complaint Submitted';
    let fromEmail = email || process.env.EMAIL_USER;
    let text = `A new complaint has been submitted.\n\n` +
      `From: ${email ? email : 'Authenticated User: ' + userId}\n` +
      `Message: ${sanitizedMessage}\n` +
      `Timestamp: ${complaint.createdAt}`;
    
    try {
      let mailResult = await transporter.sendMail({
        from: fromEmail,
        to: supportEmail,
        subject,
        text
      });
      console.log('Email sent:', mailResult);
    } catch (mailErr) {
      console.error('Nodemailer error:', mailErr);
      throw mailErr;
    }

    res.status(201).json({ message: 'Complaint submitted successfully.' });
  } catch (error) {
    console.error('Complaint error:', error);
    res.status(500).json({ error: 'Server error while submitting complaint.' });
  }
});

app.listen(port,() => {
  console.log(`Node.js server listening at http://localhost:${port}`);
});
