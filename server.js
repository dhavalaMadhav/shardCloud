require('dotenv').config();
const express = require('express');
const path = require('path');
const morgan = require('morgan');
const cors = require('cors');
const bcrypt = require("bcryptjs");

const cookieParser = require('cookie-parser');

require("./db/connection");
const { User, File } = require('./db/register') // Need both User and File models
const auth = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 5173;

app.use(morgan('tiny'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Serve static client files
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  maxAge: '1h'
}));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Home page
app.get('/', (req, res) => {
  res.render('index');
});

// Dashboard with userId injection
app.get('/dashboard', auth, (req, res) => {
  res.render('client', { 
    name: req.user.name,
    userId: req.user._id.toString()
  });  
});

// Login page
app.get("/login", (req, res) => {
  if (req.cookies.jwt) {
    return res.redirect("/dashboard");
  }
  res.render("login");
});

// Sign up page
app.get('/signin', (req, res) => {
  res.render('signin');
});

// Register user
app.post("/register", async (req, res) => {
  try {
    console.log(req.body);
    const registerUsers = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password
    });

    const token = await registerUsers.generateAuthToken();
    res.cookie("jwt", token, {
      expires: new Date(Date.now() + 60 * 60 * 1000),
      httpOnly: true,
      secure: false
    });

    await registerUsers.save();
    console.log("User registered successfully");
    res.status(201).redirect(`dashboard`);
  } catch (err) {
    console.error("Registration error:", err);
    res.send("emails should be unique");
  }
});

// Login user
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(401).send("Invalid email or password");
    }

    const ismatch = await bcrypt.compare(password, user.password);
    if (ismatch) {
      const token = await user.generateAuthToken();

      res.cookie("jwt", token, {
        expires: new Date(Date.now() + 60 * 60 * 1000),
        httpOnly: true,
        secure: false
      });

      res.status(201).redirect(`dashboard`);
    } else {
      res.status(401).send("Invalid email or password");
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("An error occurred while logging in");
  }
});

// Save file metadata to File collection and reference in User
app.post('/files', auth, async (req, res) => {
  try {
    console.log('Received file metadata:', req.body); // Debug what's actually received
    const { fileId, filename, size, mimeType, path, storageRoot, hash } = req.body;
    
    // Validate required fields explicitly
    if (!fileId || !filename || size == null || size === undefined) {
      console.error('Missing required fields:', { fileId, filename, size });
      return res.status(400).json({ 
        error: 'Missing required fields: fileId, filename, and size are required',
        received: { fileId, filename, size }
      });
    }

    // Convert size to number if it's a string
    const numericSize = typeof size === 'string' ? parseInt(size, 10) : size;
    if (isNaN(numericSize)) {
      return res.status(400).json({ error: 'Size must be a valid number' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check for duplicate fileId in user's files array
    if (user.files.some(f => f.fileId === fileId && f.status !== 'deleted')) {
      return res.status(400).json({ error: 'File with this ID already exists' });
    }

    // Push file metadata to user's files array with all required fields
    const fileData = {
      fileId,
      filename,
      size: numericSize,
      mimeType: mimeType || 'application/octet-stream',
      path: path || '',
      storageRoot: storageRoot || 'default',
      hash: hash || '',
      uploadedAt: new Date(),
      status: 'active'
    };

    console.log('Adding file to user:', fileData); // Debug what's being saved

    user.files.push(fileData);
    await user.save();

    res.status(201).json({ 
      message: 'File metadata saved successfully',
      fileCount: user.files.length
    });
  } catch (error) {
    console.error('File save error:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: `Validation error: ${error.message}`,
        details: error.errors
      });
    }
    
    res.status(500).json({ error: `Server error: ${error.message}` });
  }
});


// Get user's files using populate to get full file information
app.get('/users/:userId/files', auth, async (req, res) => {
  try {
    // Ensure user can only access their own files
    if (req.params.userId !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Find user and populate files array with full file documents
    const user = await User.findById(req.user._id).populate({
      path: 'files',
      match: { status: 'active' }, // Only get active files
      options: { sort: { uploadedAt: -1 } } // Sort by most recent
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user.files);
  } catch (error) {
    console.error('Files fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

// Delete file and remove reference from user
app.delete('/files/:fileId', auth, async (req, res) => {
  try {
    // Find the file and ensure it belongs to the authenticated user
    const file = await File.findOne({ 
      fileId: req.params.fileId,
      owner: req.user._id 
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Soft delete the file
    file.status = 'deleted';
    file.deletedAt = new Date();
    await file.save();

    // Remove file reference from user's files array
    await User.findByIdAndUpdate(
      req.user._id, 
      { $pull: { files: file._id } }
    );

    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('File delete error:', error);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Download file (proxy to storage server)
app.get('/files/:fileId/download', auth, async (req, res) => {
  try {
    const file = await File.findOne({ 
      fileId: req.params.fileId,
      owner: req.user._id,
      status: 'active'
    });

    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Proxy download request to storage server
    const storageUrl = `http://localhost:3000/files/${file.fileId}/download`;
    res.redirect(storageUrl);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

// Logout user
app.get('/logout', auth, async (req, res) => {
  try {
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      path: "/"
    });
    
    req.user.tokens = req.user.tokens.filter((token) => token.token !== req.cookies.jwt);
    await req.user.save();
    res.redirect("/login");
  } catch (error) {
    console.error("Error during logout:", error);
    res.redirect("/login");
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Client server at http://localhost:${PORT}`);
  console.log(`Ensure your storage API is running at http://localhost:3000`);
});
