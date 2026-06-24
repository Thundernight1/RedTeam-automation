import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm'

@Entity('task_results')
@Index(['mission_id'])
@Index(['agent_type', 'status'])
export class TaskResult {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  mission_id!: string

  @Column({ type: 'varchar', nullable: true })
  agent_id!: string

  @Column({ type: 'varchar' })
  agent_type!: string

  @Column({ type: 'varchar' })
  target!: string

  @Column({ type: 'varchar', default: 'pending' })
  status!: string

  @Column({ type: 'json', nullable: true })
  findings!: string

  @Column({ type: 'float', default: 0 })
  risk_score!: number

  @Column({ type: 'float', nullable: true })
  execution_time!: number

  @Column({ type: 'json', nullable: true })
  raw_output!: string

  @Column({ type: Date, nullable: true })
  started_at!: Date | null

  @Column({ type: Date, nullable: true })
  completed_at!: Date | null

  @CreateDateColumn()
  created_at!: Date
}
