import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm'

@Entity('audit_log')
@Index(['event_type', 'created_at'])
@Index(['actor'])
export class AuditLog {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  event_type!: string

  @Column({ type: 'varchar', nullable: true })
  actor!: string

  @Column({ type: 'varchar', nullable: true })
  resource_type!: string

  @Column({ type: 'varchar', nullable: true })
  resource_id!: string

  @Column({ type: 'varchar', nullable: true })
  action!: string

  @Column({ type: 'json', nullable: true })
  details!: string

  @Column({ type: 'varchar', nullable: true })
  ip_address!: string

  @CreateDateColumn()
  created_at!: Date
}
