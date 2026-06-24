/**
 * Job entity representing async background jobs (scans, recon, exploitation, triage, reporting)
 */
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, OneToMany, Index, JoinColumn } from 'typeorm'
import { User } from './User.js'
import { Program } from './Program.js'

export type JobType = 'recon' | 'scanning' | 'exploitation' | 'triage' | 'reporting'
export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

@Entity('jobs')
@Index(['status', 'created_at'])
@Index(['user_id', 'job_type'])
@Index(['program_id', 'status'])
export class Job {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  user_id!: string

  @Column({ type: 'varchar', nullable: true })
  program_id!: string

  @Column({ type: 'varchar', enum: ['recon', 'scanning', 'exploitation', 'triage', 'reporting'] })
  job_type!: JobType

  @Column({ type: 'varchar', enum: ['pending', 'running', 'completed', 'failed', 'cancelled'], default: 'pending' })
  status!: JobStatus

  @Column({ type: 'json', nullable: true })
  parameters!: Record<string, unknown>

  @Column({ type: 'json', nullable: true })
  results!: Record<string, unknown>

  @Column({ type: 'text', nullable: true })
  error_message!: string

  @Column({ type: 'int', default: 0 })
  retry_count!: number

  @Column({ type: Date, nullable: true })
  started_at!: Date

  @Column({ type: Date, nullable: true })
  completed_at!: Date

  @CreateDateColumn()
  created_at!: Date

  @UpdateDateColumn()
  updated_at!: Date

  @ManyToOne(() => User)
  @JoinColumn({ name: 'user_id' })
  user!: User

  @ManyToOne(() => Program)
  @JoinColumn({ name: 'program_id' })
  program!: Program

  isActive(): boolean {
    return ['pending', 'running'].includes(this.status)
  }

  getDuration(): number | null {
    if (!this.started_at) return null
    const end = this.completed_at || new Date()
    return end.getTime() - this.started_at.getTime()
  }
}
