import "reflect-metadata"
import { DataSource } from "typeorm"
import { User } from '../entities/User.js'
import { Program } from '../entities/Program.js'
import { Finding } from '../entities/Finding.js'
import { Report } from '../entities/Report.js'
import { Mission } from '../entities/Mission.js'
import { TaskResult } from '../entities/TaskResult.js'
import { ScopeAgreement } from '../entities/ScopeAgreement.js'
import { AgentHealth } from '../entities/AgentHealth.js'
import { AuditLog } from '../entities/AuditLog.js'
import { Job } from '../entities/Job.js'
import { JobLog } from '../entities/JobLog.js'
import { ApiKey } from '../entities/ApiKey.js'

const entities = [User, Program, Finding, Report, Mission, TaskResult, ScopeAgreement, AgentHealth, AuditLog, Job, JobLog, ApiKey]

// Parse DATABASE_URL or fall back to individual variables
const parseDatabaseConfig = () => {
    const dbUrl = process.env.DATABASE_URL || process.env.POSTGRES_URL;
    if (dbUrl) {
        try {
            const url = new URL(dbUrl);
            return {
                host: url.hostname,
                port: parseInt(url.port, 10) || 5432,
                username: url.username || 'postgres',
                password: url.password || process.env.DATABASE_PASSWORD || '',
                database: url.pathname.slice(1) || 'redteam_automation',
            };
        } catch {
            // Fall through to individual variables
        }
    }
    return {
        host: process.env.POSTGRES_HOST || process.env.DATABASE_HOST || "localhost",
        port: parseInt(process.env.POSTGRES_PORT || process.env.DATABASE_PORT || "5432", 10),
        username: process.env.POSTGRES_USER || process.env.DATABASE_USER || "postgres",
        password: process.env.POSTGRES_PASSWORD || process.env.DATABASE_PASSWORD || "",
        database: process.env.POSTGRES_DB || process.env.DATABASE_NAME || "redteam_automation",
    };
};

const dbConfig = parseDatabaseConfig();

// Enable synchronize by default so a fresh Docker install creates tables automatically.
// Only disable it explicitly in production if migrations are provided.
const shouldSynchronize = process.env.TYPEORM_SYNCHRONIZE === 'true'
    || process.env.TYPEORM_SYNCHRONIZE === undefined
    || (process.env.NODE_ENV !== "production");

const isTest = process.env.NODE_ENV === 'test'

export const AppDataSource = new DataSource(
    isTest
        ? {
            type: "better-sqlite3",
            database: ":memory:",
            synchronize: true,
            logging: false,
            entities,
            migrations: [],
            subscribers: [],
        }
        : {
            type: "postgres",
            host: dbConfig.host,
            port: dbConfig.port,
            username: dbConfig.username,
            password: dbConfig.password,
            database: dbConfig.database,
            synchronize: shouldSynchronize,
            logging: shouldSynchronize,
            entities,
            migrations: [],
            subscribers: [],
        }
)

export const initializeDatabase = async () => {
    try {
        await AppDataSource.initialize()
        if (!isTest) {
            console.log("✅ Data Source has been initialized!")
        }

        // Create default admin user if not exists
        const userRepository = AppDataSource.getRepository(User)
        const adminEmail = process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com'
        const existingAdmin = await userRepository.findOne({ where: { email: adminEmail } })

        if (!existingAdmin) {
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || ''
            const adminUser = userRepository.create({
                email: adminEmail,
                name: 'RedTeam Admin',
                password_hash: defaultPassword, // This will be hashed by the User entity's BeforeInsert hook
                role: 'admin'
            })
            await userRepository.save(adminUser)
            if (!isTest) {
                console.log(`✅ Default admin user created! Email: ${adminEmail}`)
            }
        } else {
            // Update password just in case they forgot it during testing
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || ''
            existingAdmin.password_hash = defaultPassword // Hash it again
            await userRepository.save(existingAdmin)
            if (!isTest) {
                console.log(`✅ Default admin user verified! Email: ${adminEmail}`)
            }
        }

    } catch (err) {
        const message = (err as Error)?.message || String(err)
        if (isTest) {
            throw new Error(`Test database initialization failed: ${message}`)
        }
        console.warn("⚠️  Database not available - continuing without database. Some features will be limited:", message)
    }
}
