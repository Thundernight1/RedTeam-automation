/**
 * JobLog entity for tracking job execution logs and triage notes
 */
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne, Index, JoinColumn } from 'typeorm'
import { Job } from './Job.js'

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

@Entity('job_logs')
@Index(['job_id', 'log_level'])
@Index(['created_at'])
export class JobLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  job_id!: string

  @Column({ type: 'varchar', enum: ['debug', 'info', 'warn', 'error'], default: 'info' })
  log_level!: LogLevel

  @Column({ type: 'text' })
  message!: string

  @Column({ type: 'json', nullable: true })
  metadata!: Record<string, unknown>

  @CreateDateColumn()
  created_at!: Date

  @ManyToOne(() => Job)
  @JoinColumn({ name: 'job_id' })
  job!: Job
}
