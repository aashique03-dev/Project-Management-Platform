# Backend Review

This document summarises a professional review of the backend portion of the Project Management Platform.  The review touches on architecture, security, code quality, database design, API design, missing features, and actionable changes.

---
## 1. Architecture Review

- **Project structure**: Follows a basic `src` layout with `controllers`, `models`, `routes`, `middlewares`, `utils`, `validators` and `db`.  This matches common Express/MVC patterns.
- **MVC separation**: Controllers contain business logic but no service layer; models are simple.  Some logic (token generation, aggregation pipelines) could be extracted to service/util modules.
- **Folder organisation & naming**: Most folders are sensible.  A few naming inconsistencies exist (`task.models.js` exports `Taks` typo, `constants.js` spells `AvailableTaskStatues` vs `AvailableTaskStatus`).
- **Scalability**: Structure is fine for a small project.  To scale consider splitting controllers into smaller services, adding a `services/` layer, and separating routes by resource.
- **Routing gaps**: `task.controllers.js` contains placeholder comments (`//chai`) and there is no `task.routes.js`.  This indicates incomplete implementation.

---
## 2. Security Review

- **JWT handling**:
  - Access/refresh tokens generated via user methods.  Good rotation on refresh.
  - Access token stored in cookie with `httpOnly` and `secure` flags.  `secure:true` will block non‑HTTPS local development; consider conditionally setting it or using `sameSite`.
  - Bearer header extraction uses `replace("Bearar ", "")` (typo) which may silently fail; also look for casing.

- **Refresh token logic**:
  - Stored on user document and compared on refresh; old token replaced.  No explicit blacklist for revoked tokens aside from wiping on logout.
  - Refresh endpoint accepts token from cookie or body but uses identical verification; missing expiry checks beyond JWT itself.

- **Cookie security**:
  - `sameSite` attribute not set; should consider `lax` or `strict` depending on front‑end deployment.
  - No `maxAge` or `expires` defined; cookies rely on browser session.

- **Password hashing**:
  - Bcrypt salt rounds fixed at `10` in pre‑save.  Acceptable, but make rounds configurable.

- **Validation**:
  - `express-validator` used and `validate` middleware applied to most public endpoints.  Some controllers bypass validation (e.g., `updateProject`, membership endpoints).  Input is not type‑checked in all places.

- **Role‑based access control**:
  - `validateProjectPermission` middleware enforces membership/role when accessing project endpoints.  However it is missing the required imports (`ProjectMember`, `mongoose`) which will throw a ReferenceError at runtime.
  - There is no enforcement of roles on task-related operations (which are also not exposed yet).

- **Miscellaneous security issues**:
  - Some controllers use `crypto` in `verifyEmail` but that module is not imported; will crash and disable the endpoint.

---
## 3. Code Quality Review

- **DRY violations / duplicated logic**:
  - Token generation occurs in both `generateAccessAndRefreshToken` and within user model methods; consider moving to a shared token utility.
  - Email sending logic duplicated between registration and resend flows; could reuse a helper.

- **Bad patterns**:
  - Controllers perform heavy aggregation pipelines; move these to model static methods for readability/testability.
  - Error messages spelling mistakes (`somethin`, `recieved`, `Eamil`, etc.) reduce professionalism.

- **Async handling**:
  - `asyncHandler` wrapper is used consistently, which is good.  Some routes still construct promises manually (e.g., `generateAccessAndRefreshToken`) but handle errors with try/catch.

- **Middleware usage**:
  - Validation and auth middlewares are applied correctly to most routes.  File naming `authRoute` vs `healthCheckRouter` inconsistent (capitalisation), but minor.

- **Typos / runtime bugs**:
  - `Taks` typo in model export; `AvailableTaskStatues` vs `AvailableTaskStatus` constant; `verifyJwt` header string spelled "Bearar"; `res.staus` in `getTasks` and `createTask`; missing imports as noted above; `user.save({ validateBeforeSave: flase })` typo in `verifyEmail`.

---
## 4. Database Design Review

- **Relationships**: References between users, projects, tasks, subtasks, and members are via ObjectId and `ref`.  This is appropriate.
- **Indexes**: Only unique indexes on email/username and project name.  Consider adding indexes on foreign key fields (`project` on Task/Subtask, `user`+`project` on ProjectMember) to speed lookups.
- **Query efficiency**: Aggregation pipelines in controllers are complex but run on small collections.  They could be optimized or moved into model `statics`.
- **Schema design**: Models are minimal; missing validation on some fields (e.g. `description` length).  Attachment URLs stored directly; consider separate file documents if large.

---
## 5. API Design Review

- **REST conventions**: Endpoints follow resource-based patterns (`/projects`, `/projects/:id/members`).  Some responses use status `201` on GETs (`getTasks`), which is incorrect.
- **Endpoint structure**: Missing task routes; inconsistent pluralisation (`/healthcheck` vs `/healthchech` route file).  Check for typos.
- **Response consistency**: All responses wrapped in `ApiResponse` providing `statusCode`, `data`, `message`, `success`.  Error handling via `ApiError` is consistent.
- **Error handling**: Central error middleware returns JSON.  Some thrown errors use wrong status codes (e.g. 489 for invalid reset token; unusual non‑standard).  Some error messages leak internal details.

---
## 6. Missing Features or Improvements

- **Rate limiting**: No throttling on public endpoints (login, register, password reset). Add `express-rate-limit`.
- **Logging**: No structured request/response logging (morgan, Winston). Useful for debugging/monitoring.
- **Caching**: Consider caching frequently read data (project list) with Redis.
- **Testing**: No tests present. Introduce unit and integration tests using Jest/Mocha and Supertest.
- **Monitoring**: Metrics and health checks beyond simple `/healthcheck` could be added (e.g. Prometheus, Sentry for errors).
- **Input sanitisation**: Libraries like `express-mongo-sanitize`, `helmet` are missing.
- **OpenAPI / documentation**: No API docs or swagger.

---
## 7. Changes To Implement

Below is a list of concrete improvements to implement.

1. **File**: `src/middlewares/auth.middlewares.js`  
   **Change**: Import `ProjectMember` and `mongoose`, fix Bearer header string, add `sameSite` option to cookies.  
   **Reason**: Middleware currently references undefined variables and typo prevents token extraction.

2. **File**: `src/controllers/auth.controllers.js`  
   **Change**: Add `import crypto from "crypto"` at top; fix typos (`flase`, message spellings); reduce duplication by moving token persistence logic to utility; use constant for cookie options; add expiry/secure conditionals.  
   **Reason**: `verifyEmail` will crash due to missing import; code cleanliness and security improvements.

3. **File**: `src/models/task.models.js`  
   **Change**: Correct export name from `Taks` to `Task`; fix constant name `AvailableTaskStatues` to `AvailableTaskStatus` in `constants.js` and imports.  
   **Reason**: Typo will cause runtime errors when requiring Task model.

4. **File**: `src/utils/constants.js`  
   **Change**: Rename `AvailableTaskStatues` to `AvailableTaskStatus`; fix `TaskStatusEnum.TOTDO` to `TODO`.  
   **Reason**: Maintainability and avoid silent bugs.

5. **File**: `src/controllers/project.controllers.js` and others using aggregation  
   **Change**: Move expensive aggregation pipelines into static model methods (e.g. `ProjectMember.getUserProjects(userId)`).  
   **Reason**: Improves testability and reuse; keeps controllers thin.

6. **File**: `src/routes/project.routes.js`  
   **Change**: Add validation middleware to update endpoints; check incoming parameters.  
   **Reason**: Prevent invalid data being saved.

7. **File**: create `src/routes/task.routes.js` for the missing task API; wire it into `app.js` at `/api/v1/projects/:projectId/tasks`.  
   **Reason**: Task controllers exist but are unexposed; routes are required for frontend integration.

8. **File**: add indexes in model definitions, e.g. `taskSchema.index({ project: 1 })`, `projectMemberSchema.index({ project:1, user:1 }, { unique: true })`.  
   **Reason**: Query performance on large datasets.

9. **File**: apply rate limiter in `src/app.js` for auth endpoints.  
   **Reason**: Protect against brute force.

10. **File**: add global security middlewares (`helmet`, `express-mongo-sanitize`) in `src/app.js`.  
    **Reason**: Basic hardening of HTTP headers and payload sanitisation.

11. **File**: update error codes/messages in `auth.controllers.js` (e.g. use 401 for invalid token, avoid 489).  
    **Reason**: Align with HTTP standards and improve client handling.

12. **File**: `src/utils/mail.js`  
    **Change**: fix variable name `forgotPAsswordMailgenContent` spelling and export consistency.  
    **Reason**: Typos risk confusion.

13. **File**: add environment conditional around `secure` cookie option or allow override via config.  
    **Reason**: Development should work without HTTPS.

14. **File**: add test stubs under `test/` and configure CI.  
    **Reason**: Ensure regression safety.

15. **File**: update `.env.example` to list required variables (`ACCESS_TOKEN_SECRET`, etc.).  
    **Reason**: Improve onboarding.

---

This review highlights current strengths (clear separation, consistent error wrapper) and points to technical debt or missing pieces that should be addressed before production deployment. Once the above changes are made, the backend will be more secure, maintainable, and ready for integration with the React frontend.
