import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

import { env } from './config/env';
import { corsOptions } from './config/cors';
import { errorHandler, notFoundHandler } from './middleware/error-handler';
import { attachTenantContext } from './middleware/tenant-middleware';
import { rules, validate } from './middleware/validate';
import { requireAlumni } from './middleware/auth-middleware';
import { alumniController } from './controllers/alumni-controller';

// Module routes
import adminRoutes from './modules/admin/admin-routes';
import studentRoutes from './modules/student/student-routes';
import alumniRoutes from './modules/alumni/alumni-routes';
import featureRoutes from './modules/features/feature-routes';
import socialRoutes from './modules/social/social-routes';

import logger from './utils/logger';
import prisma from './prisma/client';

const app = express();
const alumniAuthAliasRouter = express.Router();

// ── Security Middleware ────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ── Rate Limiting ─────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/admin/login', authLimiter);
app.use('/api/student/login', authLimiter);
app.use('/api/alumni-auth/login', authLimiter);
app.use('/api/alumni/login', authLimiter);

// ── Body Parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// ── Health Check ──────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), version: '3.0.0' });
});

// ── Tenant Context (global) ───────────────────────────────────────────────────
app.use('/api', attachTenantContext);

// ── Routes ────────────────────────────────────────────────────────────────────
alumniAuthAliasRouter.post('/register', rules.alumniRegister, validate, alumniController.register);
alumniAuthAliasRouter.post('/login', rules.alumniLogin, validate, alumniController.login);
alumniAuthAliasRouter.get('/profile', ...requireAlumni, alumniController.getProfile);
alumniAuthAliasRouter.put('/profile', ...requireAlumni, rules.alumniProfileUpdate, validate, alumniController.updateProfile);
alumniAuthAliasRouter.patch('/profile', ...requireAlumni, rules.alumniProfileUpdate, validate, alumniController.updateProfile);
alumniAuthAliasRouter.get('/dashboard', ...requireAlumni, alumniController.getDashboard);

app.use('/api/admin', adminRoutes);
app.use('/api/student', studentRoutes);
app.use('/api/students', studentRoutes);
app.use('/api/alumni', alumniRoutes);
app.use('/api/alumni-auth', alumniAuthAliasRouter);
app.use('/api', featureRoutes);
app.use('/api', socialRoutes);

// ── 404 & Error Handlers ──────────────────────────────────────────────────────
app.use(notFoundHandler);
app.use(errorHandler);

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function bootstrap(): Promise<void> {
  try {
    await prisma.$connect();
    logger.info('✅ Database connected via Prisma');

    const collegeCount = await prisma.college.count();
    if (collegeCount === 0) {
      logger.info('🌱 Empty database detected: creating default colleges...');
      await prisma.college.createMany({
        data: [
          { id: 'skit', name: 'SKIT College of Engineering', subdomain: 'skit', location: 'Jaipur, Rajasthan', code: 'SKIT' },
          { id: 'nps', name: 'National Public School', subdomain: 'nps', location: 'Bangalore, Karnataka', code: 'NPS' },
          { id: 'christ', name: 'Christ University', subdomain: 'christ', location: 'Bangalore, Karnataka', code: 'CHRIST' },
          { id: 'rv', name: 'RV College of Engineering', subdomain: 'rv', location: 'Bangalore, Karnataka', code: 'RVCE' },
        ],
        skipDuplicates: true,
      });
      logger.info('✅ Default colleges auto-created');
    }

    const studentCount = await prisma.student.count();
    if (studentCount === 0) {
      logger.info('🌱 Empty student table: creating demo student, alumni, and admin accounts...');
      const studentHash = await bcrypt.hash('secret123', 10);
      const adminHash = await bcrypt.hash('admin123', 10);

      const colleges = ['skit', 'nps', 'christ', 'rv'];
      for (const col of colleges) {
        await prisma.admin.createMany({
          data: [{
            collegeId: col,
            email: `admin@${col}.alumni.local`,
            username: `admin_${col}`,
            fullName: `Admin ${col.toUpperCase()}`,
            passwordHash: adminHash,
            isActive: true,
          }],
          skipDuplicates: true,
        });

        await prisma.student.createMany({
          data: [{
            collegeId: col,
            email: `student0001.${col}@alumni.local`,
            passwordHash: studentHash,
            fullName: `Demo Student ${col.toUpperCase()}`,
            department: 'CSE',
            year: 4,
            rollNumber: `${col.toUpperCase()}001`,
            phone: '9876543210',
            bio: `Student at ${col.toUpperCase()}`,
            headline: 'Aspiring Software Engineer',
            location: 'Bangalore, India',
            skills: 'JavaScript, React, Node.js',
            isActive: true,
            isApproved: true,
          }],
          skipDuplicates: true,
        });

        await prisma.alumni.createMany({
          data: [{
            collegeId: col,
            email: `alumni0001.${col}@alumni.local`,
            passwordHash: studentHash,
            fullName: `Demo Alumni ${col.toUpperCase()}`,
            department: 'CSE',
            graduationYear: 2023,
            company: 'Google',
            designation: 'Software Engineer',
            phone: '9876543211',
            bio: `Alumni at ${col.toUpperCase()}`,
            headline: 'Software Engineer @ Google',
            location: 'Bangalore, India',
            skills: 'TypeScript, React, Node.js, Cloud',
            availableMentorship: true,
            availableReferral: true,
            status: 'approved',
            isActive: true,
            isApproved: true,
          }],
          skipDuplicates: true,
        });
      }
      logger.info('✅ Demo accounts auto-created');
    }

    app.listen(env.PORT, () => {
      logger.info(`🚀 Server running on port ${env.PORT} [${env.NODE_ENV}]`);
    });
  } catch (err) {
    logger.error('Failed to start server', err);
    await prisma.$disconnect();
    process.exit(1);
  }
}

process.on('SIGTERM', async () => {
  logger.info('SIGTERM received — shutting down gracefully');
  await prisma.$disconnect();
  process.exit(0);
});

process.on('SIGINT', async () => {
  await prisma.$disconnect();
  process.exit(0);
});

bootstrap().catch((err) => {
  logger.error('Bootstrap failed', err);
  process.exit(1);
});

export default app;
