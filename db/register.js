const mongoose = require('mongoose');
const { Schema } = mongoose;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Subdocument schema for a user's files (embedded)
const FileSubSchema = new Schema(
  {
    fileId: { type: String, required: true },     // UUID from upload server
    filename: { type: String, required: true },   // original name
    size: { type: Number, required: true },
    mimeType: { type: String },
    path: { type: String },                       // absolute/relative path on storage
    storageRoot: { type: String },                // which storage root/provider
    uploadedAt: { type: Date, default: Date.now },
    hash: { type: String },                       // optional integrity/duplicate check
    status: { type: String, enum: ['active','deleted'], default: 'active' },
    deletedAt: { type: Date }
  },
  { _id: true, timestamps: true } // each subdoc gets its own _id
);

// User schema now embeds an array of file subdocuments
const UserSchema = new Schema(
  {
    name: { type: String, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, index: true },
    password: { type: String, required: true },
    tokens: [{ token: { type: String, required: true } }],
    files: { type: [FileSubSchema], default: [] } // all this user's files live here
  },
  { timestamps: true }
);

// Enforce per-user uniqueness of fileId within the embedded files array
UserSchema.path('files').validate(function(files) {
  const ids = files.map(f => f.fileId);
  return ids.length === new Set(ids).size;
}, 'Duplicate fileId in user files.');

// Convenience methods for managing embedded files
UserSchema.methods.addFile = async function(fileData) {
  // Prevent duplicates defensively
  if (this.files.some(f => f.fileId === fileData.fileId)) {
    throw new Error('fileId already exists for this user');
  }
  this.files.push(fileData);
  return this.save();
};

UserSchema.methods.listFiles = function({ includeDeleted = false } = {}) {
  return this.files
    .filter(f => includeDeleted || f.status !== 'deleted')
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
