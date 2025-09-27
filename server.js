require('dotenv').config();
const express = require('express');
const path = require('path');
const morgan = require('morgan');
const cors = require('cors');
const bcrypt = require("bcryptjs");
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

require("./db/connection");
const { User, File } = require('./db/register')
const auth = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 5173;

// UPDATED: Multiple storage node configuration with your specific IPs
const STORAGE_NODES = [
  {
    id: 'node1',
    url: process.env.STORAGE_NODE_1_URL || 'http://192.168.35.137:3000',
    name: 'Primary Storage Node',
    priority: 1
  },
  {
    id: 'node2', 
    url: process.env.STORAGE_NODE_2_URL || 'http://192.168.35.140:3000',
    name: 'Secondary Storage Node',
    priority: 2
  }
];

const NODE_ENV = process.env.NODE_ENV || 'development';

console.log(`🌍 Environment: ${NODE_ENV}`);
console.log(`📡 Storage nodes configured:`);
STORAGE_NODES.forEach(node => {
  console.log(`   ${node.name}: ${node.url}`);
});

// Node selection and health management
class NodeManager {
  constructor(nodes) {
    this.nodes = nodes;
    this.lastHealthCheck = 0;
    this.healthCheckInterval = 30000; // 30 seconds
    this.nodeHealth = new Map();
    
    // Initialize all nodes as healthy
    this.nodes.forEach(node => {
      this.nodeHealth.set(node.id, { 
        healthy: true, 
        latency: Infinity,
        lastChecked: 0 
      });
    });
  }

  async testNodeLatency(node) {
    const startTime = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      console.log(`🔍 Testing node: ${node.name} at ${node.url}`);
      
      const response = await fetch(`${node.url}/health`, {
        method: 'HEAD',
        signal: controller.signal,
        headers: { 
          'Content-Type': 'application/json',
          'User-Agent': 'ShardCloud-Platform/1.0'
        }
      });
      
      clearTimeout(timeoutId);
      const latency = Date.now() - startTime;
      
      console.log(`✅ ${node.name} responded in ${latency}ms`);
      
      return {
        ...node,
        healthy: response.ok,
        latency,
        status: response.ok ? 'healthy' : 'unhealthy',
        statusCode: response.status
      };
    } catch (error) {
      console.log(`❌ ${node.name} failed: ${error.message}`);
      
      return {
        ...node,
        healthy: false,
        latency: Infinity,
        status: 'unreachable',
        error: error.message
      };
    }
  }

  async checkAllNodesHealth() {
    console.log('\n🔍 Checking health of all storage nodes...');
    
    const healthChecks = this.nodes.map(node => this.testNodeLatency(node));
    const results = await Promise.all(healthChecks);
    
    // Update health status
    results.forEach(result => {
      this.nodeHealth.set(result.id, {
        healthy: result.healthy,
        latency: result.latency,
        lastChecked: Date.now(),
        status: result.status,
        error: result.error,
        statusCode: result.statusCode
      });
      
      const statusIcon = result.healthy ? '✅' : '❌';
      console.log(`${statusIcon} ${result.name} (${result.url}): ${result.status} - ${result.latency}ms`);
    });

    this.lastHealthCheck = Date.now();
    return results;
  }

  async getNearestHealthyNode() {
    // Check if we need to refresh health status
    if (Date.now() - this.lastHealthCheck > this.healthCheckInterval) {
      await this.checkAllNodesHealth();
    }

    // Get healthy nodes sorted by latency
    const healthyNodes = this.nodes
      .filter(node => this.nodeHealth.get(node.id)?.healthy)
      .map(node => ({
        ...node,
        ...this.nodeHealth.get(node.id)
      }))
      .sort((a, b) => a.latency - b.latency);

    if (healthyNodes.length === 0) {
      console.error('❌ No healthy storage nodes available!');
      console.log('Available nodes status:');
      this.getNodeHealth().forEach(node => {
        console.log(`   ${node.name}: ${node.status} (${node.error || 'No error'})`);
      });
      return null;
    }

    const selectedNode = healthyNodes[0];
    console.log(`🎯 Selected nearest node: ${selectedNode.name} at ${selectedNode.url} (${selectedNode.latency}ms)`);
    return selectedNode;
  }

  getNodeHealth() {
    return Array.from(this.nodeHealth.entries()).map(([nodeId, health]) => {
      const node = this.nodes.find(n => n.id === nodeId);
      return {
        ...node,
        ...health
      };
    });
  }

  // Force refresh node health
  async forceHealthCheck() {
    this.lastHealthCheck = 0;
    return await this.checkAllNodesHealth();
  }
}

// Initialize node manager
const nodeManager = new NodeManager(STORAGE_NODES);

// CORS configuration
app.use(cors({
  origin: '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

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

// Utility functions
function chunkFile(buffer, numChunks = 5) {
  const chunkSize = Math.ceil(buffer.length / numChunks);
  const chunks = [];
  
  for (let i = 0; i < numChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, buffer.length);
    chunks.push(buffer.slice(start, end));
  }
  
  return chunks;
}

function generateFileId() {
  return crypto.randomBytes(16).toString('hex');
}

// UPDATED: Helper function to communicate with selected storage node
async function makeStorageRequest(endpoint, options = {}) {
  const selectedNode = await nodeManager.getNearestHealthyNode();
  
  if (!selectedNode) {
    throw new Error('No healthy storage nodes available');
  }

  const url = `${selectedNode.url}${endpoint}`;
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
    },
    timeout: 30000
  };
  
  const finalOptions = { ...defaultOptions, ...options };
  
  try {
    console.log(`📡 Making request to storage node: ${selectedNode.name} - ${url}`);
    const response = await fetch(url, finalOptions);
    return { response, selectedNode };
  } catch (error) {
    console.error(`❌ Storage node request failed to ${selectedNode.name}: ${error.message}`);
    
    // Mark node as unhealthy and retry with another node
    nodeManager.nodeHealth.set(selectedNode.id, {
      ...nodeManager.nodeHealth.get(selectedNode.id),
      healthy: false,
      lastChecked: Date.now(),
      error: error.message
    });
    
    throw new Error(`Storage node communication error: ${error.message}`);
  }
}

// Home page
app.get('/', (req, res) => {
  res.render('index');
});

// UPDATED: Dashboard with multiple storage nodes info
app.get('/dashboard', auth, async (req, res) => {
  try {
    if (!req.user) {
      console.error('req.user is null after auth middleware');
      return res.redirect('/login');
    }

    if (!req.user.name || !req.user.email) {
      console.error('User missing required fields:', {
        hasName: !!req.user.name,
        hasEmail: !!req.user.email,
        userId: req.user._id
      });
      return res.status(500).send('User data incomplete. Please log in again.');
    }

    // Get current storage nodes status
    let nearestNode = null;
    let allNodesStatus = [];
    
    try {
      nearestNode = await nodeManager.getNearestHealthyNode();
      allNodesStatus = nodeManager.getNodeHealth();
    } catch (error) {
      console.error('Error getting node status:', error);
      allNodesStatus = nodeManager.getNodeHealth();
    }

    res.render('client', { 
      name: req.user.name,
      userId: req.user._id.toString(),
      userEmail: req.user.email,
      storageNodes: STORAGE_NODES,
      nearestNode: nearestNode,
      nodesStatus: allNodesStatus
    });
  } catch (error) {
    console.error('Dashboard route error:', error);
    res.status(500).send('Server error. Please try again.');
  }
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
      secure: NODE_ENV === 'production'
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
    console.log(`Login attempt for email: ${email}`);
    
    const user = await User.findOne({ email });
    
    if (!user) {
      console.log(`User not found: ${email}`);
      return res.status(401).send("Invalid email or password");
    }

    console.log(`User found: ${user.email}, checking password...`);
    const ismatch = await bcrypt.compare(password, user.password);
    
    if (ismatch) {
      const token = await user.generateAuthToken();
      console.log(`Login successful for: ${user.email}`);

      res.cookie("jwt", token, {
        expires: new Date(Date.now() + 60 * 60 * 1000),
        httpOnly: true,
        secure: NODE_ENV === 'production'
      });

      res.status(201).redirect(`dashboard`);
    } else {
      console.log(`Password mismatch for: ${email}`);
      res.status(401).send("Invalid email or password");
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("An error occurred while logging in");
  }
});

// UPDATED: Get nearest storage node endpoint
app.get('/storage/nearest', auth, async (req, res) => {
  try {
    const nearestNode = await nodeManager.getNearestHealthyNode();
    
    if (!nearestNode) {
      return res.status(503).json({ 
        error: 'No healthy storage nodes available',
        nodes: nodeManager.getNodeHealth(),
        availableNodes: STORAGE_NODES
      });
    }

    res.json({
      nearestNode: {
        id: nearestNode.id,
        url: nearestNode.url,
        name: nearestNode.name,
        latency: nearestNode.latency,
        status: nearestNode.status
      },
      allNodes: nodeManager.getNodeHealth(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Nearest node selection error:', error);
    res.status(500).json({ 
      error: 'Failed to select storage node',
      details: error.message,
      nodes: nodeManager.getNodeHealth()
    });
  }
});

// NEW: Force refresh node health
app.post('/storage/refresh', auth, async (req, res) => {
  try {
    console.log('🔄 Forcing health check refresh...');
    const healthResults = await nodeManager.forceHealthCheck();
    
    res.json({
      message: 'Node health refreshed successfully',
      timestamp: new Date().toISOString(),
      results: healthResults
    });
  } catch (error) {
    console.error('Health refresh error:', error);
    res.status(500).json({ 
      error: 'Failed to refresh node health',
      details: error.message
    });
  }
});

// UPDATED: Chunked file upload endpoint
app.post('/files', auth, async (req, res) => {
  try {
    console.log('\n=== DATABASE SAVE REQUEST ===');
    console.log('Request body keys:', Object.keys(req.body));
    
    const { fileId, filename, size, mimeType, userEmail, chunkCount, chunks } = req.body;
    
    // Field validation
    const fieldCheck = {
      fileId: { value: fileId, valid: !!fileId },
      filename: { value: filename, valid: !!filename },
      size: { value: size, valid: size != null && size !== undefined },
      userEmail: { value: userEmail, valid: !!userEmail },
      chunks: { 
        value: chunks, 
        valid: Array.isArray(chunks) && chunks.length > 0,
        length: Array.isArray(chunks) ? chunks.length : 'not-array'
      }
    };

    console.log('Field validation:', fieldCheck);
    
    const missingFields = Object.entries(fieldCheck)
      .filter(([_, check]) => !check.valid)
      .map(([field, _]) => field);
    
    if (missingFields.length > 0) {
      console.error('Missing or invalid fields:', missingFields);
      return res.status(400).json({ 
        error: `Missing or invalid required fields: ${missingFields.join(', ')}`,
        received: fieldCheck
      });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check for duplicate fileId
    if (user.files.some(f => f.fileId === fileId && f.status !== 'deleted')) {
      return res.status(400).json({ error: 'File with this ID already exists' });
    }

    const numericSize = typeof size === 'string' ? parseInt(size, 10) : size;
    if (isNaN(numericSize)) {
      return res.status(400).json({ error: 'Size must be a valid number' });
    }

    // Get the node that was used for storing chunks
    const selectedNode = await nodeManager.getNearestHealthyNode();
    if (!selectedNode) {
      console.error('No storage nodes available for file save');
      return res.status(503).json({ 
        error: 'No healthy storage nodes available',
        availableNodes: STORAGE_NODES.map(n => ({ name: n.name, url: n.url }))
      });
    }

    console.log(`💾 Saving file metadata for storage on: ${selectedNode.name} (${selectedNode.url})`);

    // Create file data with selected storage node info
    const fileData = {
      fileId,
      filename,
      size: numericSize,
      mimeType: mimeType || 'application/octet-stream',
      path: `users/${userEmail}/${fileId}`,
      storageRoot: 'chunked',
      userEmail,
      chunkCount: chunkCount || 5,
      chunks: chunks.map(chunk => ({
        index: chunk.index,
        path: chunk.path,
        size: chunk.size,
        uploadedAt: chunk.uploadedAt || new Date()
      })),
      isChunked: true,
      uploadedAt: new Date(),
      status: chunks.length === (chunkCount || 5) ? 'active' : 'incomplete',
      storageNodeId: selectedNode.id,
      storageNodeUrl: selectedNode.url,
      storageNodeName: selectedNode.name
    };

    // Save to database
    user.files.push(fileData);
    await user.save();

    console.log('✅ File metadata saved to database');
    console.log(`📡 File chunks stored on: ${selectedNode.name} (${selectedNode.url})`);

    res.status(201).json({ 
      message: 'Chunked file metadata saved successfully',
      fileCount: user.files.length,
      isComplete: fileData.status === 'active',
      chunksReceived: chunks.length,
      storageNode: {
        id: selectedNode.id,
        name: selectedNode.name,
        url: selectedNode.url,
        latency: selectedNode.latency
      }
    });
    
  } catch (error) {
    console.error('Chunked file save error:', error);
    
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        error: `Validation error: ${error.message}`,
        details: error.errors
      });
    }
    
    res.status(500).json({ error: `Server error: ${error.message}` });
  }
});

// Get user's files
app.get('/users/:userId/files', auth, async (req, res) => {
  try {
    if (req.params.userId !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const activeFiles = user.files
      .filter(f => f.status === 'active')
      .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt))
      .map(file => ({
        ...file.toObject(),
        storageNodeInfo: {
          id: file.storageNodeId,
          name: file.storageNodeName,
          url: file.storageNodeUrl
        }
      }));

    console.log(`Retrieved ${activeFiles.length} active files for user ${user.email}`);
    res.json(activeFiles);
  } catch (error) {
    console.error('Files fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

// UPDATED: Download endpoint - uses specific storage node for each file
app.get('/files/:fileId/download', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const file = user.files.find(f => f.fileId === req.params.fileId && f.status === 'active');
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Use the specific storage node where this file was stored
    const storageNodeUrl = file.storageNodeUrl || STORAGE_NODES[0].url;
    const downloadUrl = `${storageNodeUrl}/files/${file.fileId}/download?userEmail=${encodeURIComponent(file.userEmail)}`;
    
    console.log(`📥 Redirecting download to storage node: ${file.storageNodeName || 'Default'} - ${downloadUrl}`);
    res.redirect(downloadUrl);
    
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

// UPDATED: Delete file from specific storage node
app.delete('/files/:fileId', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const file = user.files.find(f => f.fileId === req.params.fileId && f.status === 'active');
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Mark file as deleted in database first
    file.status = 'deleted';
    file.deletedAt = new Date();
    await user.save();

    // Delete from the specific storage node where this file was stored
    try {
      const storageNodeUrl = file.storageNodeUrl || STORAGE_NODES[0].url;
      const deleteUrl = `${storageNodeUrl}/files/${req.params.fileId}?userEmail=${encodeURIComponent(user.email)}`;
      
      console.log(`🗑️ Deleting from storage node: ${file.storageNodeName} - ${deleteUrl}`);
      
      const response = await fetch(deleteUrl, { 
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        const result = await response.json();
        console.log(`✅ File deleted from storage node: ${file.storageNodeName}`, result);
      } else {
        console.error('❌ Storage node deletion failed:', response.status);
      }
      
    } catch (storageError) {
      console.error('❌ Storage node deletion error:', storageError.message);
    }

    res.json({ 
      message: 'File deleted successfully',
      fileId: req.params.fileId,
      filename: file.filename,
      storageNode: file.storageNodeName || 'Unknown'
    });
  } catch (error) {
    console.error('File delete error:', error);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// UPDATED: Check all storage nodes health
app.get('/storage/health', auth, async (req, res) => {
  try {
    const healthResults = await nodeManager.checkAllNodesHealth();
    
    res.json({
      timestamp: new Date().toISOString(),
      totalNodes: STORAGE_NODES.length,
      healthyNodes: healthResults.filter(n => n.healthy).length,
      nodes: healthResults.map(node => ({
        id: node.id,
        name: node.name,
        url: node.url,
        status: node.status,
        latency: node.latency,
        healthy: node.healthy,
        error: node.error || null,
        lastChecked: new Date(nodeManager.nodeHealth.get(node.id)?.lastChecked || 0).toISOString()
      }))
    });
  } catch (error) {
    res.status(503).json({
      timestamp: new Date().toISOString(),
      error: error.message,
      nodes: nodeManager.getNodeHealth()
    });
  }
});

// UPDATED: Debug endpoint
app.get('/debug/user', auth, async (req, res) => {
  let nearestNode = null;
  
  try {
    nearestNode = await nodeManager.getNearestHealthyNode();
  } catch (error) {
    console.error('Error getting nearest node for debug:', error);
  }
  
  res.json({
    user: {
      id: req.user._id,
      name: req.user.name,
      email: req.user.email,
      fileCount: req.user.files ? req.user.files.length : 0,
      files: req.user.files ? req.user.files.map(f => ({
        fileId: f.fileId,
        filename: f.filename,
        status: f.status,
        storageNode: {
          id: f.storageNodeId,
          name: f.storageNodeName,
          url: f.storageNodeUrl
        }
      })) : []
    },
    config: {
      storageNodes: STORAGE_NODES,
      nearestNode: nearestNode,
      environment: NODE_ENV,
      nodesHealth: nodeManager.getNodeHealth()
    }
  });
});

// Logout user
app.get('/logout', auth, async (req, res) => {
  try {
    res.clearCookie("jwt", {
      httpOnly: true,
      secure: NODE_ENV === "production",
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

// Start server and perform initial health check
app.listen(PORT, 'localhost', async () => {
  console.log(`🚀 ShardCloud Platform server running on http://localhost:${PORT}`);
  console.log(`📡 Storage nodes configured: ${STORAGE_NODES.length}`);
  STORAGE_NODES.forEach((node, index) => {
    console.log(`   📊 Node ${index + 1}: ${node.name} at ${node.url}`);
  });
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🔧 Debug endpoint: http://localhost:${PORT}/debug/user`);
  console.log(`🏥 Storage health: http://localhost:${PORT}/storage/health`);
  console.log(`🎯 Nearest node: http://localhost:${PORT}/storage/nearest`);
  console.log(`🔄 Refresh nodes: http://localhost:${PORT}/storage/refresh`);
  
  // Perform initial health check
  console.log('\n🔍 Performing initial health check...');
  try {
    const healthResults = await nodeManager.checkAllNodesHealth();
    const healthyCount = healthResults.filter(n => n.healthy).length;
    console.log(`✅ Health check complete: ${healthyCount}/${STORAGE_NODES.length} nodes healthy`);
    
    if (healthyCount === 0) {
      console.log('⚠️  WARNING: No storage nodes are currently healthy!');
      console.log('   Make sure your storage servers are running at:');
      STORAGE_NODES.forEach(node => {
        console.log(`   - ${node.url}`);
      });
    }
  } catch (error) {
    console.error('❌ Initial health check failed:', error.message);
  }
});
