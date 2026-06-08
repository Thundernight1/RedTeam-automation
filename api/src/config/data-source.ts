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
                password: url.password || 'postgres',
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
        password: process.env.POSTGRES_PASSWORD || process.env.DATABASE_PASSWORD || "postgres",
        database: process.env.POSTGRES_DB || process.env.DATABASE_NAME || "redteam_automation",
    };
};

const dbConfig = parseDatabaseConfig();

// Enable synchronize if explicitly set or in non-production environments
const shouldSynchronize = process.env.TYPEORM_SYNCHRONIZE === 'true' 
    || (process.env.NODE_ENV !== "production");

export const AppDataSource = new DataSource({
    type: "postgres",
    host: dbConfig.host,
    port: dbConfig.port,
    username: dbConfig.username,
    password: dbConfig.password,
    database: dbConfig.database,
    synchronize: shouldSynchronize,
    logging: shouldSynchronize,
    entities: [User, Program, Finding, Report, Mission, TaskResult, ScopeAgreement, AgentHealth, AuditLog, Job, JobLog, ApiKey],
    migrations: [],
    subscribers: [],
})

export const initializeDatabase = async () => {
    try {
        await AppDataSource.initialize()
        console.log("✅ Data Source has been initialized!")

        // Create default admin user if not exists
        const userRepository = AppDataSource.getRepository(User)
        const adminEmail = process.env.DEFAULT_ADMIN_EMAIL || 'admin@cybersurhub.com'
        const existingAdmin = await userRepository.findOne({ where: { email: adminEmail } })

        if (!existingAdmin) {
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin@12345!'
            const adminUser = userRepository.create({
                email: adminEmail,
                name: 'RedTeam Admin',
                password_hash: defaultPassword, // This will be hashed by the User entity's BeforeInsert hook
                role: 'admin'
            })
            await userRepository.save(adminUser)
            console.log(`✅ Default admin user created! Email: ${adminEmail}`)
        } else {
            // Update password just in case they forgot it during testing
            const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'Admin@12345!'
            existingAdmin.password_hash = defaultPassword // Hash it again
            await userRepository.save(existingAdmin)
            console.log(`✅ Default admin user verified! Email: ${adminEmail}`)
        }

    } catch (err) {
        const message = (err as Error)?.message || String(err)
        console.warn("⚠️  Database not available - continuing without database. Some features will be limited:", message)
    }
}
