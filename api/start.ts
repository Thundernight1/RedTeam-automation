import dotenv from 'dotenv'
dotenv.config()

const requiredVars = ['JWT_SECRET']
const missing = requiredVars.filter((key) => !process.env[key])

if (missing.length > 0) {
  console.error('[FATAL] Missing required environment variables:')
  for (const key of missing) {
    console.error(`  - ${key}`)
  }
  console.error('[FATAL] Copy .env.example to .env, set the required secrets, and restart.')
  process.exit(1)
}

await import('./server.js')
