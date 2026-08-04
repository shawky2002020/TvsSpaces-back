# TVS Spaces Startup & Deployment Instructions

This document outlines startup procedures and configurations for local development and production environments.

## 1. Environment Variables Configuration

| Variable | Description | Default (Local) | Production Recommendation |
| :--- | :--- | :--- | :--- |
| `SPRING_PROFILES_ACTIVE` | Target Spring Boot profile | `local` | `prod` |
| `DB_URL` | JDBC database connection string | `jdbc:mysql://localhost:3306/mydatabase` | Managed database instance (e.g. AWS RDS) |
| `DB_USERNAME` | Database username | `myuser` | Strong service account username |
| `DB_PASSWORD` | Database password | `secret` | Strong secret password |
| `JWT_SECRET` | 256-bit signature secret key | `yoursecretkeyyoursecretkeyyoursecretkey` | High entropy random string (>= 32 chars) |
| `JWT_ACCESS_EXPIRATION` | Access token lifespan (ms) | `900000` (15 min) | `900000` (15 min) |
| `JWT_REFRESH_EXPIRATION` | Refresh token lifespan (ms) | `604800000` (7 days) | `604800000` (7 days) |
| `CORS_ALLOWED_ORIGINS` | Permitted API request origins | `http://localhost:4200` | Frontend domain url (e.g. `https://tvs-spaces.com`) |
| `COOKIE_SECURE` | HttpOnly cookie secure flag | `false` | `true` (Requires HTTPS) |
| `COOKIE_SAME_SITE` | Cookie SameSite policy | `Strict` | `Strict` |

---

## 2. Local Startup Instructions

### Step 2.1: Start the MySQL Database
Navigate to the `server/` directory and spin up the docker compose container:
```bash
docker compose up -d
```
This runs MySQL on `localhost:3306`.

### Step 2.2: Compile & Run the Spring Boot Server
Launch the Spring Boot application using Maven:
```bash
# Windows PowerShell
.\mvnw.cmd spring-boot:run

# Bash/Git Bash
./mvnw spring-boot:run
```
Migrations will execute automatically via Flyway on database initialization.

### Step 2.3: Start the Angular Frontend
Navigate to the `client/` directory, install packages, and start the development server:
```bash
npm install
npm start
```
The application will be accessible at `http://localhost:4200`.

---

## 3. Docker Production Deployment

To run the complete system inside containers, package the backend using the Dockerfile and configure a reverse proxy (e.g., Nginx) to route traffic to `/api` for the backend and serve the compiled Angular bundles under `client/dist/myApp`.
