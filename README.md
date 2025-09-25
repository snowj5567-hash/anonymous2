# 🛡️ Static Malware Analysis API

A comprehensive web-based malware analysis platform that combines traditional static analysis techniques with AI-powered classification to detect and analyze malicious files.

## 🚀 Features

### 🔍 **Advanced File Analysis**
- **Multi-format Support**: PE executables, ELF files, APK files, Office documents, PDFs
- **Archive Extraction**: Password-protected ZIP, RAR, and 7z archives
- **Static Analysis**: Entropy analysis, string extraction, header analysis
- **Visualization**: Entropy plots and section analysis charts
- **Suspicious Pattern Detection**: Identifies malicious APIs, permissions, and keywords

### 🤖 **AI-Powered Classification**
- **Malware Family Detection**: Identifies specific malware families
- **Confidence Scoring**: Probability-based classification results
- **Real-time Analysis**: Fast processing with external AI model integration
- **Duplicate Detection**: Prevents re-analysis of previously analyzed files

### 🔐 **Security & Authentication**
- **JWT Authentication**: Secure token-based authentication
- **OAuth Integration**: Google and GitHub OAuth support
- **Role-based Access**: Different user roles and permissions
- **Input Validation**: Comprehensive security validation
- **XSS Protection**: Built-in cross-site scripting protection
- **Rate Limiting**: IP-based rate limiting for API endpoints

### 📊 **User Management**
- **User Profiles**: Track upload history and analysis results
- **Guest Access**: Anonymous file analysis capability
- **Upload History**: Paginated analysis history
- **Email Notifications**: Automated complaint notifications

### 🛠️ **Support System**
- **Complaint System**: User feedback and support requests
- **Email Integration**: Automated email alerts
- **Rate Limiting**: 5 complaints per hour per IP
- **Input Sanitization**: Security validation for all inputs

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Node.js API   │    │   Python        │
│   (Client)      │◄──►│   (Express)     │◄──►│   Analyzer      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                              ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   MongoDB       │    │   AI Model      │
                       │   Database      │    │   (External)    │
                       └─────────────────┘    └─────────────────┘
```

## 🛠️ Technology Stack

### **Backend**
- **Node.js** (v20) - Express.js server
- **Python** (v3) - Static analysis engine
- **MongoDB** - Data persistence
- **JWT** - Authentication
- **Passport.js** - OAuth strategies

### **Analysis Tools**
- **pefile** - PE file analysis
- **pyelftools** - ELF file analysis
- **androguard** - APK analysis
- **python-magic** - File type detection
- **ssdeep** - Fuzzy hashing
- **matplotlib** - Data visualization
- **scipy** - Statistical analysis

### **Security**
- **bcryptjs** - Password hashing
- **express-rate-limit** - Rate limiting
- **express-session** - Session management
- **cors** - Cross-origin resource sharing

## 📦 Installation & Setup

### **Prerequisites**
- Docker
- Node.js 20+
- Python 3.8+
- MongoDB (or MongoDB Atlas)

### **Local Development**

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd anonymous-api
   ```

2. **Install dependencies**
   ```bash
   # Node.js dependencies
   npm install
   
   # Python dependencies
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r py-scripts/requirements.txt
   pip install -r py-scripts/requirements-extra.txt
   ```

3. **Configure environment**
   ```bash
   cp config.env.example config.env
   # Edit config.env with your settings
   ```

4. **Start the server**
   ```bash
   npm start
   ```

### **Docker Deployment**

1. **Build the image**
   ```bash
   docker build -t malware-analyzer .
   ```

2. **Run the container**
   ```bash
   docker run -p 3000:3000 --env-file config.env malware-analyzer
   ```

## 🔧 Configuration

### **Environment Variables**

Create a `config.env` file with the following variables:

```env
# Database
DB_URI=mongodb+srv://username:password@cluster.mongodb.net/database

# JWT
JWT_SECRET=your-super-secret-jwt-key

# AI Model
AI_MODEL_URL=https://your-ai-model-endpoint/predict
AI_MODEL_TOKEN=your-ai-model-token

# Email (for complaints)
SUPPORT_EMAIL=support@yourdomain.com
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# OAuth (optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_CALLBACK_BASE=http://localhost:3000
```

## 📡 API Endpoints

### **Authentication**
- `POST /signup` - User registration
- `POST /login` - User authentication
- `GET /auth/google` - Google OAuth
- `GET /auth/github` - GitHub OAuth

### **File Analysis**
- `POST /upload` - Upload and analyze files
  - Supports single files and archives
  - Optional password for protected archives
  - Returns comprehensive analysis results

### **User Management**
- `GET /profile` - User profile with analysis history
  - Requires authentication
  - Paginated results

### **Support**
- `POST /complaints` - Submit complaints/feedback
  - Rate limited: 5 per hour per IP
  - Supports both authenticated and guest users

## 🔍 Analysis Features

### **Static Analysis**
- **File Identification**: Magic number detection, file type analysis
- **Hash Generation**: MD5, SHA1, SHA256, SSDeep fuzzy hashing
- **Entropy Analysis**: Shannon entropy calculation with visualization
- **String Extraction**: ASCII and Unicode string analysis
- **Suspicious Pattern Detection**: Malware keywords, IP addresses, URLs

### **Format-Specific Analysis**

#### **PE Files (Windows Executables)**
- Architecture detection (32/64-bit)
- Import/Export analysis
- Section entropy analysis
- Rich header information
- Digital signature verification
- Packer detection

#### **ELF Files (Linux Executables)**
- Architecture detection
- Section and segment analysis
- Symbol table analysis
- Import/export symbol detection

#### **APK Files (Android Applications)**
- Package information
- Permission analysis
- Component analysis (activities, services, receivers)
- Certificate information
- Dangerous permission detection

#### **Office Documents**
- VBA macro detection
- OLE object analysis
- Embedded file detection
- Suspicious content identification

#### **PDF Files**
- Version and page count
- JavaScript detection
- Embedded file analysis
- Action analysis

### **AI Classification**
- **File Classification**: Malicious vs Benign
- **Family Detection**: Specific malware family identification
- **Confidence Scoring**: Probability-based results
- **Real-time Processing**: Fast AI model integration

## 🔒 Security Features

### **Input Validation**
- File size limits (1KB - 25MB)
- File type validation
- Message length restrictions (1-1000 characters)
- XSS pattern detection and blocking

### **Rate Limiting**
- **Complaints**: 5 per hour per IP
- **Uploads**: Configurable limits
- **Authentication**: Protection against brute force

### **Data Protection**
- Password hashing with bcrypt
- JWT token authentication
- Input sanitization
- Secure session management

## 📊 Usage Examples

### **Upload and Analyze a File**
```bash
curl -X POST http://localhost:3000/upload \
  -F "file=@suspicious_file.exe" \
  -F "password=archive_password"  # Optional
```

### **Submit a Complaint**
```bash
curl -X POST http://localhost:3000/complaints \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "message": "Found an issue with the analysis"
  }'
```

### **Get User Profile**
```bash
curl -X GET http://localhost:3000/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## 🚀 Deployment

### **Docker Deployment**
```bash
# Build production image
docker build -t malware-analyzer:production .

# Run with environment variables
docker run -d \
  -p 3000:3000 \
  --env-file config.env \
  --name malware-api \
  malware-analyzer:production
```

### **Environment Considerations**
- **Production**: Use production-grade MongoDB
- **Scaling**: Consider horizontal scaling with load balancers
- **Monitoring**: Implement logging and monitoring
- **Backup**: Regular database backups
- **SSL**: Use HTTPS in production

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the ISC License.

## ⚠️ Disclaimer

This tool is designed for legitimate security research and malware analysis. Users are responsible for ensuring they have proper authorization to analyze any files. The authors are not responsible for any misuse of this software.

## 🆘 Support

For support and questions:
- Submit issues through the repository
- Use the complaints endpoint in the API
- Contact: support@yourdomain.com

---

**Built with ❤️ for the cybersecurity community** 