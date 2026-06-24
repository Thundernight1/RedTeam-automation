/**
 * Report entity representing security assessment reports
 */
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, Index, JoinColumn, OneToMany } from 'typeorm'
import { User } from './User.js'
import { Finding } from './Finding.js'

export type ReportStatus = 'draft' | 'submitted' | 'reviewed' | 'approved' | 'rejected'
export type ReportType = 'vulnerability_assessment' | 'penetration_test' | 'security_audit' | 'compliance_check'

@Entity('reports')
@Index(['status', 'created_at'])
@Index(['created_by_id', 'created_at'])
export class Report {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  title!: string

  @Column({ type: 'text' })
  summary!: string

  @Column({ type: 'text', nullable: true })
  executive_summary!: string

  @Column({ type: 'text', nullable: true })
  methodology!: string

  @Column({ type: 'text', nullable: true })
  scope!: string

  @Column({ type: 'varchar', enum: ['draft', 'submitted', 'reviewed', 'approved', 'rejected'], default: 'draft' })
  status!: ReportStatus

  @Column({ type: 'varchar', enum: ['vulnerability_assessment', 'penetration_test', 'security_audit', 'compliance_check'] })
  type!: ReportType

  @Column({ type: 'json', nullable: true })
  target_info!: {
    name: string
    url: string
    ip_range: string[]
    description: string
  }

  @Column({ type: 'json', nullable: true })
  risk_assessment!: {
    overall_risk: 'critical' | 'high' | 'medium' | 'low'
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
    informational_count: number
  }

  @Column({ type: 'json', nullable: true })
  recommendations!: {
    immediate: string[]
    short_term: string[]
    long_term: string[]
  }

  @Column({ type: 'json', nullable: true })
  metadata!: Record<string, unknown>

  @Column({ type: Date, nullable: true })
  submitted_at!: Date

  @Column({ type: Date, nullable: true })
  reviewed_at!: Date

  @Column({ type: Date, nullable: true })
  approved_at!: Date

  @CreateDateColumn({ name: 'created_at' })
  created_at!: Date

  @UpdateDateColumn({ name: 'updated_at' })
  updated_at!: Date

  @Column({ name: 'created_by_id', type: 'varchar', nullable: true })
  created_by_id!: string

  @ManyToOne(() => User, user => user.reports)
  @JoinColumn({ name: 'created_by_id' })
  created_by!: User

  @OneToMany(() => Finding, finding => finding.report)
  findings!: Finding[]

  // Get total findings count
  getTotalFindings(): number {
    return this.findings?.length || 0
  }

  // Get findings by severity
  getFindingsBySeverity(severity: 'critical' | 'high' | 'medium' | 'low' | 'informational'): number {
    return this.findings?.filter(f => f.severity === severity).length || 0
  }

  // Check if report can be edited
  canEdit(): boolean {
    return this.status === 'draft'
  }

  // Submit report for review
  submit(): void {
    if (this.status === 'draft') {
      this.status = 'submitted'
      this.submitted_at = new Date()
    }
  }
}
