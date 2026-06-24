import winston from 'winston';
import fs from 'fs';
import path from 'path';

// Ensure logs directory exists
const logDir = process.env.LOG_DIR || 'logs';
try {
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }
} catch (error) {
  console.error(`Failed to create log directory ${logDir}:`, error);
  process.exit(1);
}

// Validate log level
const validLogLevels = ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'];
const logLevel = process.env.LOG_LEVEL || 'info';
if (!validLogLevels.includes(logLevel)) {
  console.error(`Invalid LOG_LEVEL: ${logLevel}. Must be one of: ${validLogLevels.join(', ')}`);
  process.exit(1);
}

// Validate environment
const validEnvironments = ['development', 'testing', 'staging', 'production'];
const environment = process.env.NODE_ENV || 'development';
if (!validEnvironments.includes(environment)) {
  console.error(`Invalid NODE_ENV: ${environment}. Must be one of: ${validEnvironments.join(', ')}`);
  process.exit(1);
}

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

const logger = winston.createLogger({
  level: logLevel,
  format: logFormat,
  defaultMeta: {
    service: 'ZumrutAutomation',
    environment: environment,
    timestamp: new Date().toISOString(),
  },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.printf(({ timestamp, level, message, component, ...meta }) => {
          const componentStr = component ? `[${component}]` : '';
          return `${timestamp} ${level} ${componentStr}: ${message} ${
            Object.keys(meta).length ? JSON.stringify(meta) : ''
          }`;
        })
      ),
      handleExceptions: true,
      handleRejections: true,
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error',
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 5,
      tailable: true,
      handleExceptions: true,
      handleRejections: true,
    }),
    new winston.transports.File({
      filename: path.join(logDir, 'combined.log'),
      maxsize: 10 * 1024 * 1024, // 10MB
      maxFiles: 10,
      tailable: true,
      handleExceptions: true,
      handleRejections: true,
    }),
  ],
  exitOnError: false,
});

// Create separate loggers for different concerns
export const authLogger = logger.child({ component: 'authentication' });
export const apiLogger = logger.child({ component: 'api' });
export const dbLogger = logger.child({ component: 'database' });
export const securityLogger = logger.child({ component: 'security' });

// Add stream for HTTP logging compatibility
export const stream = {
  write: (message: string) => {
    logger.info(message.trim());
  },
};

// Handle uncaught exceptions and unhandled rejections
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

export default logger;