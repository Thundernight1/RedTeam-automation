/**
 * Finding entity representing security vulnerabilities discovered
 */
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, Index, JoinColumn } from 'typeorm'
import { User } from './User.js'
import { Program } from './Program.js'
import { Report } from './Report.js'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational'
export type FindingStatus = 'submitted' | 'triaged' | 'resolved' | 'duplicate' | 'not_applicable' | 'spam'
export type FindingType = 'xss' | 'sql_injection' | 'authentication_bypass' | 'authorization_bypass' | 'information_disclosure' | 'business_logic' | 'other'

@Entity('findings')
@Index(['severity', 'status'])
@Index(['researcher_id', 'created_at'])
@Index(['program_id', 'status'])
export class Finding {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  title: string

  @Column({ type: 'text' })
  description: string

  @Column({ type: 'text', nullable: true })
  technical_details: string

  @Column({ type: 'text', nullable: true })
  reproduction_steps: string

  @Column({ type: 'text', nullable: true })
  impact: string

  @Column({ type: 'text', nullable: true })
  remediation: string

  @Column({ type: 'varchar', enum: ['critical', 'high', 'medium', 'low', 'informational'] })
  severity: Severity

  @Column({ type: 'varchar', enum: ['xss', 'sql_injection', 'authentication_bypass', 'authorization_bypass', 'information_disclosure', 'business_logic', 'other'] })
  type: FindingType

  @Column({ type: 'varchar', enum: ['submitted', 'triaged', 'resolved', 'duplicate', 'not_applicable', 'spam'], default: 'submitted' })
  status: FindingStatus

  @Column({ type: 'json', nullable: true })
  affected_endpoints: string[]

  @Column({ type: 'json', nullable: true })
  screenshots: {
    url: string
    description: string
  }[]

  @Column({ type: 'json', nullable: true })
  metadata: Record<string, unknown>

  @Column({ type: 'decimal', precision: 10, scale: 2, nullable: true })
  estimated_reward: number

  @Column({ type: 'decimal', precision: 10, scale: 2, nullable: true })
  actual_reward: number

  @Column({ type: Date, nullable: true })
  submitted_at: Date

  @Column({ type: Date, nullable: true })
  triaged_at: Date

  @Column({ type: Date, nullable: true })
  resolved_at: Date

  @CreateDateColumn()
  created_at: Date

  @UpdateDateColumn()
  updated_at: Date

  @Column({ name: 'researcher_id', type: 'varchar', nullable: true })
  researcher_id: string

  @Column({ name: 'program_id', type: 'varchar', nullable: true })
  program_id: string

  @ManyToOne(() => User, user => user.findings)
  @JoinColumn({ name: 'researcher_id' })
  researcher: User

  @ManyToOne(() => Program, program => program.findings)
  @JoinColumn({ name: 'program_id' })
  program: Program

  @Column({ name: 'report_id', type: 'varchar', nullable: true })
  report_id: string

  @ManyToOne(() => Report, report => report.findings)
  @JoinColumn({ name: 'report_id' })
  report: Report

  // Get CVSS score based on severity
  getCvssScore(): number {
    const scores = {
      critical: 9.0,
      high: 7.0,
      medium: 4.0,
      low: 2.0,
      informational: 0.0
    }
    return scores[this.severity] || 0.0
  }

  // Check if finding is active (not resolved or duplicate)
  isActive(): boolean {
    return !['resolved', 'duplicate', 'not_applicable', 'spam'].includes(this.status)
  }

  // Get reward status
  getRewardStatus(): 'pending' | 'approved' | 'paid' | 'none' {
    if (this.actual_reward) return 'paid'
    if (this.estimated_reward && this.status === 'resolved') return 'approved'
    if (this.estimated_reward) return 'pending'
    return 'none'
  }
}
