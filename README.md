# Project Management Platform

A robust, full-featured project management API built with Node.js, Express, and MongoDB. This platform enables teams to collaborate efficiently with role-based access control, project management, task tracking, and subtask organization.

## 🎯 Features

### Core Functionality
- **User Management**: User registration, login, email verification, and password reset
- **Project Management**: Create, update, delete, and manage projects with detailed descriptions
- **Role-Based Access Control (RBAC)**: Admin, Project Admin, and Member roles with granular permissions
- **Task Management**: Create, track, and manage tasks within projects with status tracking (Todo, In Progress, Done)
- **Subtasks**: Break down tasks into smaller subtasks with completion tracking
- **Project Members**: Add team members to projects with role assignments
- **Project Notes**: Attach notes and documentation to projects
- **File Attachments**: Upload files to tasks with metadata tracking

### Security & Authentication
- **JWT Authentication**: Secure token-based authentication with access and refresh tokens
- **Password Security**: bcrypt hashing for password storage
- **Email Verification**: Email-based account verification with token expiry
- **Password Recovery**: Forgot password flow with secure token-based reset
- **Role-Based Permissions**: Fine-grained access control at project and resource levels
- **Secure Cookies**: HttpOnly and Secure cookie flags for token storage

### Developer Experience
- **Input Validation**: Express-validator for comprehensive request validation
- **Error Handling**: Centralized error handling with custom ApiError class
- **Consistent Response Format**: Standardized ApiResponse wrapper for all endpoints
- **Async Handler**: Wrapper for handling async errors in route handlers
- **CORS Support**: Configurable CORS with environment-based origin management

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Runtime** | Node.js (ES Modules) |
| **Framework** | Express.js 5.2.1 |
| **Database** | MongoDB 9.2.1 (Mongoose ODM) |
| **Authentication** | JWT (jsonwebtoken 9.0.3) |
| **Password Hashing** | bcrypt 6.0.0 |
| **Validation** | express-validator 7.3.1 |
| **Email Service** | Nodemailer 8.0.1 + Mailgen 2.0.32 |
| **File Upload** | Multer (disk storage) |
| **CORS** | cors 2.8.6 |
| **Environment** | dotenv 17.3.1 |
| **Code Formatting** | Prettier 3.8.1 |

---

## 📁 Project Structure

```
Project Management Platform/
├── src/
│   ├── index.js                 # Entry point - server initialization
│   ├── app.js                   # Express app configuration, middleware setup
│   ├── controllers/             # Request handlers for business logic
│   │   ├── auth.controllers.js           # Authentication & user management
│   │   ├── project.controllers.js        # Project CRUD & member management
│   │   ├── task.controllers.js           # Task & subtask operations
│   │   └── healthcheck.controllers.js    # Health check endpoint
│   ├── models/                  # Mongoose schemas
│   │   ├── user.models.js                # User schema with auth methods
│   │   ├── project.models.js             # Project schema
│   │   ├── projectmember.models.js       # Project-User relationship with roles
│   │   ├── task.models.js                # Task schema
│   │   ├── subtask.models.js             # Subtask schema
│   │   └── note.models.js                # Project notes schema
│   ├── routes/                  # API route definitions
│   │   ├── auth.routes.js                # Auth endpoints
│   │   ├── project.routes.js             # Project endpoints
│   │   └── healthchech.routes.js         # Health check routes
│   ├── middlewares/             # Custom middleware functions
│   │   ├── auth.middlewares.js           # JWT verification & permission validation
│   │   ├── multer.middlewares.js         # File upload configuration
│   │   └── validators.middlewares.js     # Request validation error handling
│   ├── utils/                   # Utility functions & helpers
│   │   ├── apiError.js                   # Custom error class
│   │   ├── apiResponse.js                # Standard response wrapper
│   │   ├── async-handler.js              # Async error wrapper
│   │   ├── constants.js                  # Enums and constants (roles, statuses)
│   │   └── mail.js                       # Email service & templates
│   ├── validators/              # Express-validator rule definitions
│   │   └── index.js                      # Validation rules for all routes
│   └── db/
│       └── index.js                      # MongoDB connection setup
├── public/
│   └── images/                  # Uploaded file storage
├── .env                         # Environment variables (not in repo)
├── package.json                 # Dependencies & scripts
└── README.md                    # This file
```

### Directory Purpose

- **controllers/**: Business logic for handling requests, database operations, and response formatting
- **models/**: Mongoose schema definitions with embedded methods (JWT generation, password hashing)
- **routes/**: HTTP route mapping with middleware chain integration
- **middlewares/**: Request interceptors for auth, validation, and file handling
- **utils/**: Reusable helper classes and functions across the application
- **validators/**: Input validation rules using express-validator library

---

## 🔐 Authentication & Role-Based Access Control

### Authentication Flow

```
1. User Registration → Email Verification Token → Email Sent
2. User Login → Access & Refresh Token Generation → Tokens in Cookies & Response
3. Token Verification → Middleware checks JWT signature → User attached to request
4. Token Refresh → Refresh Token validated → New Access Token issued
5. Password Reset → Forgot Password Token → Email Link → Reset Password
```

### User Roles

| Role | Scope | Permissions |
|------|-------|-------------|
| **ADMIN** | Global | All system operations (future multi-tenant support) |
| **PROJECT_ADMIN** | Project-level | Create/update/delete tasks, manage members, update project |
| **MEMBER** | Project-level | View project, create/update own tasks, complete subtasks |

### Token Management

- **Access Token**: Short-lived (configurable via `ACCESS_TOKEN_EXPIRY`)
- **Refresh Token**: Long-lived (configurable via `REFRESH_TOKEN_EXPIRY`), stored in database
- **Temporary Tokens**: One-time use for email verification and password reset (20-minute expiry)

### Request Headers

```
Authorization: Bearer <accessToken>
Cookie: accessToken=<token>; refreshToken=<token>;
```

---

## 📡 Core API Endpoints

### Base URL
```
http://localhost:3000/api/v1
```

### Authentication Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/auth/register` | ❌ | Register new user |
| POST | `/auth/login` | ❌ | User login |
| GET | `/auth/verify-email/:verificationToken` | ❌ | Verify email address |
| POST | `/auth/refresh-token` | ❌ | Get new access token |
| POST | `/auth/forgot-password` | ❌ | Request password reset |
| POST | `/auth/reset-password/:resetToken` | ❌ | Reset forgotten password |
| POST | `/auth/logout` | ✅ | User logout (clear tokens) |
| POST | `/auth/current-user` | ✅ | Get authenticated user details |
| POST | `/auth/change-password` | ✅ | Change user password |
| POST | `/auth/resend-email-verification` | ✅ | Resend verification email |

### Project Endpoints
| Method | Endpoint | Auth | Role | Description |
|--------|----------|------|------|-------------|
| GET | `/projects` | ✅ | All | Get user's projects |
| POST | `/projects` | ✅ | All | Create new project |
| GET | `/projects/:projectId` | ✅ | All | Get project details |
| PUT | `/projects/:projectId` | ✅ | Admin | Update project |
| DELETE | `/projects/:projectId` | ✅ | Admin | Delete project |
| GET | `/projects/:projectId/members` | ✅ | All | List project members |
| POST | `/projects/:projectId/members` | ✅ | Admin | Add member to project |
| PUT | `/projects/:projectId/members/:userId` | ✅ | Admin | Update member role |
| DELETE | `/projects/:projectId/members/:userId` | ✅ | Admin | Remove member |

### Task Endpoints (Planned Implementation)
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/projects/:projectId/tasks` | ✅ | Get all tasks in project |
| POST | `/projects/:projectId/tasks` | ✅ | Create task |
| GET | `/projects/:projectId/tasks/:taskId` | ✅ | Get task details with subtasks |
| PUT | `/projects/:projectId/tasks/:taskId` | ✅ | Update task |
| DELETE | `/projects/:projectId/tasks/:taskId` | ✅ | Delete task |
| POST | `/projects/:projectId/tasks/:taskId/subtasks` | ✅ | Create subtask |
| PUT | `/projects/:projectId/tasks/:taskId/subtasks/:subtaskId` | ✅ | Update subtask |
| DELETE | `/projects/:projectId/tasks/:taskId/subtasks/:subtaskId` | ✅ | Delete subtask |

### Health Check
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/healthcheck` | ❌ | API health status |

#### Request/Response Examples

**Register User**
```json
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "SecurePass123!",
  "fullName": "John Doe"
}

Response (201):
{
  "success": true,
  "statusCode": 201,
  "data": {
    "user": {
      "_id": "507f1f77bcf86cd799439011",
      "email": "user@example.com",
      "username": "johndoe",
      "fullName": "John Doe",
      "isEmailVerified": false,
      "createdAt": "2024-01-15T10:30:00Z"
    }
  },
  "message": "User registered successfully and verification email has been sent"
}
```

**Create Project**
```json
POST /api/v1/projects
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "name": "Website Redesign",
  "description": "Complete redesign of company website"
}

Response (201):
{
  "success": true,
  "statusCode": 201,
  "data": {
    "_id": "507f1f77bcf86cd799439012",
    "name": "Website Redesign",
    "description": "Complete redesign of company website",
    "createdBy": "507f1f77bcf86cd799439011",
    "createdAt": "2024-01-15T10:35:00Z"
  },
  "message": "Project created successfully"
}
```

**Add Project Member**
```json
POST /api/v1/projects/:projectId/members
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "email": "teammate@example.com",
  "role": "project_admin"
}

Response (201):
{
  "success": true,
  "statusCode": 201,
  "data": {},
  "message": "Project member added successfully"
}
```

---

## 🚀 Setup Instructions

### Prerequisites
- Node.js v18+ 
- MongoDB 5.0+
- npm or yarn package manager
- Mailtrap account (for email testing)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd "Project Management Platform"
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Create environment file**
   ```bash
   cp .env.example .env
   ```

4. **Configure environment variables** (see below)

5. **Start the server**
   ```bash
   # Development (with nodemon)
   npm run dev

   # Production
   npm start
   ```

The server will listen on `http://localhost:3000`

### Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# Database
DB_URL=mongodb://localhost:27017/project-management-platform

# JWT Secrets (generate using: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
ACCESS_TOKEN_SECRET=your_access_token_secret_here_min_32_chars
ACCESS_TOKEN_EXPIRY=1h
REFRESH_TOKEN_SECRET=your_refresh_token_secret_here_min_32_chars
REFRESH_TOKEN_EXPIRY=7d

# CORS Configuration
CORS_ORIGIN=http://localhost:5173,http://localhost:3000

# Email Service (Mailtrap)
MAILTRAP_SMTP_HOST=smtp.mailtrap.io
MAILTRAP_SMTP_PORT=2525
MAILTRAP_SMTP_USER=your_mailtrap_username
MAILTRAP_SMTP_PASS=your_mailtrap_password

# Application URLs
SERVER_URL=http://localhost:3000
FORGOT_PASSWORD_REDIRECT_URL=http://localhost:5173/reset-password
```

### Environment Variable Explanation

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | 3000 | Server port |
| `DB_URL` | - | MongoDB connection string |
| `ACCESS_TOKEN_SECRET` | - | Secret key for signing access tokens |
| `ACCESS_TOKEN_EXPIRY` | 1h | Access token lifespan |
| `REFRESH_TOKEN_SECRET` | - | Secret key for signing refresh tokens |
| `REFRESH_TOKEN_EXPIRY` | 7d | Refresh token lifespan |
| `CORS_ORIGIN` | localhost:5173 | Allowed frontend origins |
| `MAILTRAP_SMTP_*` | - | Email service credentials |
| `SERVER_URL` | - | Backend URL for email links |
| `FORGOT_PASSWORD_REDIRECT_URL` | - | Frontend URL for password reset |

#### Generating Secure Secrets

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

---

## 🏗️ Architecture & Best Practices

### Design Patterns Used

1. **MVC Pattern**: Separation of Models, Views (Routes), and Controllers
2. **Middleware Pipeline**: Request flow through composed middleware functions
3. **Async Handler Wrapper**: Consistent async error handling across controllers
4. **Custom Error Class**: Centralized error management with standardized responses
5. **Factory Pattern**: Token generation methods on model instances
6. **Strategy Pattern**: Role-based permission validation middleware

### Code Organization Principles

- **Single Responsibility**: Each module handles one concern (auth, projects, tasks, etc.)
- **DRY (Don't Repeat Yourself)**: Reusable validators, middleware, and utility functions
- **Modularity**: Routes, controllers, and models cleanly separated
- **Consistency**: Standardized error handling and response formats across all endpoints

### Security Best Practices Implemented

✅ **Password Security**
- Bcrypt hashing with salt rounds (10)
- Passwords never returned in API responses
- Password change requires old password verification

✅ **JWT Tokens**
- Separate access and refresh tokens
- Refresh tokens stored in database for revocation
- Short-lived access tokens reduce exposure window
- HttpOnly and Secure cookie flags

✅ **Email Verification**
- Account email must be verified before full access
- One-time temporary tokens for verification
- Token expiry (20 minutes) prevents brute force

✅ **Password Reset**
- Secure token-based reset flow
- Temporary tokens with expiry
- No password hints in error messages

✅ **Authorization**
- Role-based access control at project level
- Middleware validates user permissions before route execution
- Project membership required for resource access

✅ **Input Validation**
- Express-validator for request data validation
- Sanitization of user inputs
- Type checking on sensitive fields

### Performance Considerations

- **Database Indexing**: Ensure indexes on frequently queried fields:
  - `User.email`, `User.username` (unique)
  - `Project.createdBy`
  - `ProjectMember.project`, `ProjectMember.user`
  - `Task.project`, `Task.assignedTo`

- **Aggregation Pipeline**: Used in `getTaskById` and `getProjectMembers` for efficient data fetching
- **Populate vs Aggregate**: Consider using aggregation for complex queries with multiple lookups
- **Connection Pooling**: MongoDB driver handles connection pooling (default 10 connections)

### Future Enhancement Recommendations

1. **Rate Limiting**: Implement express-rate-limit to prevent brute force attacks
2. **Logging**: Add structured logging (Winston, Pino) for debugging and monitoring
3. **Caching**: Redis caching for frequently accessed data (user sessions, project lists)
4. **API Versioning**: Already structured as `/api/v1/` - easy to extend
5. **Database Migrations**: Consider migration tool (db-migrate) for schema changes
6. **Testing**: Add Jest/Mocha for unit and integration testing
7. **Documentation**: Swagger/OpenAPI for interactive API documentation
8. **Task Webhooks**: Notify external systems on task status changes
9. **Real-time Updates**: WebSocket support for live collaboration
10. **Audit Logging**: Track all user actions for compliance

---

## 📋 NPM Scripts

```bash
# Start server in production mode
npm start

# Start server in development mode with auto-reload
npm run dev

# Format code with Prettier
npm run format
```

---

## 🔄 Workflow Example

### Creating a Project and Assigning Tasks

```
1. User A logs in
   POST /api/v1/auth/login
   ↓ Receives: accessToken, refreshToken

2. User A creates a project
   POST /api/v1/projects
   Headers: Authorization: Bearer <accessToken>
   Body: { name: "Mobile App", description: "..." }
   ↓ Returns: project object with _id

3. User A adds User B to project
   POST /api/v1/projects/{projectId}/members
   Body: { email: "userb@example.com", role: "project_admin" }

4. User A creates a task
   POST /api/v1/projects/{projectId}/tasks
   Body: { title: "Design UI", assignedTo: "{userBId}", status: "todo" }

5. User B logs in and views assigned tasks
   GET /api/v1/projects/{projectId}/tasks
   ↓ Sees task assigned to them

6. User B updates task status
   PUT /api/v1/projects/{projectId}/tasks/{taskId}
   Body: { status: "in_progress" }
```

---

## 📝 License

ISC License - See LICENSE file for details

---

## 👤 Author

**Aashique**
- Email: aaashique03@gmail.com
- GitHub: [aashique](https://github.com/aashique03-dev)
- LinkedIn: [Aashique](https://www.linkedin.com/in/aashique-ali-mugheri-8aa657368/)

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Last Updated**: March 2, 2026
