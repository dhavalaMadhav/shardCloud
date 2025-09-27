const mongoose = require('mongoose');
const { Schema } = mongoose;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// NEW: Chunk metadata schema
const ChunkSchema = new Schema(
  {
    index: { type: Number, required: true },      // 0, 1, 2, 3, 4
    path: { type: String, required: true },       // path to chunk file on storage
    size: { type: Number, required: true },       // size of this chunk in bytes
    uploadedAt: { type: Date, default: Date.now },
    hash: { type: String }                        // optional chunk integrity check
  },
  { _id: false } // chunks don't need their own _id
);

// UPDATED: File subdocument schema with chunking support
const FileSubSchema = new Schema(
  {
    fileId: { type: String, required: true },     // UUID from upload server
    filename: { type: String, required: true },   // original name
    size: { type: Number, required: true },       // total file size (sum of all chunks)
    mimeType: { type: String },
    path: { type: String },                       // base path for user's file directory
    storageRoot: { type: String, default: 'chunked' },
    
    // NEW: Chunking-specific fields
    userEmail: { type: String, required: true },  // redundant but useful for queries
    chunkCount: { type: Number, default: 5 },     // number of chunks (default 5)
    chunks: { type: [ChunkSchema], default: [] }, // array of chunk metadata
    isChunked: { type: Boolean, default: true },  // flag to distinguish chunked vs legacy files
    
    // Existing fields
    uploadedAt: { type: Date, default: Date.now },
    hash: { type: String },                       // optional integrity/duplicate check for full file
    status: { type: String, enum: ['active','deleted','incomplete'], default: 'incomplete' }, // incomplete until all chunks uploaded
    deletedAt: { type: Date }
  },
  { _id: true, timestamps: true }
);

// NEW: Validation for chunked files
FileSubSchema.pre('validate', function(next) {
  // If file is chunked, ensure chunk count matches chunks array length
  if (this.isChunked && this.chunks.length > 0) {
    if (this.chunks.length !== this.chunkCount) {
      return next(new Error(`Chunk count mismatch: expected ${this.chunkCount}, got ${this.chunks.length}`));
    }
    
    // Ensure all chunks have sequential indexes
    const expectedIndexes = Array.from({ length: this.chunkCount }, (_, i) => i);
    const actualIndexes = this.chunks.map(c => c.index).sort((a, b) => a - b);
    
    if (JSON.stringify(expectedIndexes) !== JSON.stringify(actualIndexes)) {
      return next(new Error('Chunk indexes must be sequential from 0 to chunkCount-1'));
    }
    
    // Mark as active if all chunks are present
    if (this.status === 'incomplete' && this.chunks.length === this.chunkCount) {
      this.status = 'active';
    }
  }
  
  // For legacy (non-chunked) files, mark as active immediately
  if (!this.isChunked && this.status === 'incomplete') {
    this.status = 'active';
  }
  
  next();
});

// NEW: Instance methods for chunked files
FileSubSchema.methods.addChunk = function(chunkData) {
  // Validate chunk index
  if (chunkData.index < 0 || chunkData.index >= this.chunkCount) {
    throw new Error(`Invalid chunk index: ${chunkData.index}`);
  }
  
  // Check if chunk already exists
  const existingChunkIndex = this.chunks.findIndex(c => c.index === chunkData.index);
  if (existingChunkIndex !== -1) {
    // Replace existing chunk
    this.chunks[existingChunkIndex] = chunkData;
  } else {
    // Add new chunk
    this.chunks.push(chunkData);
  }
  
  // Sort chunks by index
  this.chunks.sort((a, b) => a.index - b.index);
  
  // Update status if all chunks received
  if (this.chunks.length === this.chunkCount) {
    this.status = 'active';
  }
  
  return this;
};

FileSubSchema.methods.isComplete = function() {
  return this.isChunked ? 
    (this.chunks.length === this.chunkCount && this.status === 'active') : 
    (this.status === 'active');
};

FileSubSchema.methods.getTotalChunkSize = function() {
  return this.chunks.reduce((total, chunk) => total + chunk.size, 0);
};

// User schema (mostly unchanged, but with updated methods)
const UserSchema = new Schema(
  {
    name: { type: String, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, index: true },
    password: { type: String, required: true },
    tokens: [{ token: { type: String, required: true } }],
    files: { type: [FileSubSchema], default: [] }
  },
  { timestamps: true }
);

// Enhanced uniqueness validation
UserSchema.path('files').validate(function(files) {
  const ids = files.map(f => f.fileId);
  return ids.length === new Set(ids).size;
}, 'Duplicate fileId in user files.');

// UPDATED: Enhanced methods for chunked files
UserSchema.methods.addFile = async function(fileData) {
  // Set userEmail from parent user if not provided
  if (!fileData.userEmail) {
    fileData.userEmail = this.email;
  }
  
  // Prevent duplicates
  if (this.files.some(f => f.fileId === fileData.fileId)) {
    throw new Error('fileId already exists for this user');
  }
  
  this.files.push(fileData);
  return this.save();
};

UserSchema.methods.addChunkToFile = async function(fileId, chunkData) {
  const file = this.files.find(f => f.fileId === fileId);
  if (!file) {
    throw new Error('File not found');
  }
  
  file.addChunk(chunkData);
  return this.save();
};

UserSchema.methods.listFiles = function({ includeDeleted = false, includeIncomplete = false } = {}) {
  return this.files
    .filter(f => {
      if (!includeDeleted && f.status === 'deleted') return false;
      if (!includeIncomplete && f.status === 'incomplete') return false;
      return true;
    })
    .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
};

UserSchema.methods.findFileByFileId = function(fid) {
  return this.files.find(f => f.fileId === fid) || null;
};

UserSchema.methods.softDeleteFile = async function(fid) {
  const f = this.files.find(f => f.fileId === fid);
  if (!f) return false;
  f.status = 'deleted';
  f.deletedAt = new Date();
  await this.save();
  return true;
};

// NEW: Method to get incomplete uploads (for cleanup/resume)
UserSchema.methods.getIncompleteUploads = function() {
  return this.files.filter(f => f.status === 'incomplete');
};

// Existing auth methods (unchanged)
UserSchema.methods.generateAuthToken = async function() {
    const token = jwt.sign({ _id: this._id.toString()}, process.env.SECRET_KEY);
    this.tokens = this.tokens.concat({ token: token }); 
    await this.save();
    console.log(`token generated: ${token}`);
    return token;
}

UserSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);
const File = mongoose.models.File || mongoose.model('File', FileSubSchema);

module.exports = { User, File };
