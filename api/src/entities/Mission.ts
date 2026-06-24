import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, Index } from 'typeorm'

export type MissionStatus = 'pending' | 'validating' | 'queued' | 'dispatching' | 'in_progress' | 'aggregating' | 'completed' | 'failed' | 'aborted'

@Entity('missions')
@Index(['status', 'created_at'])
@Index(['client_name'])
export class Mission {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  mission_id!: string

  @Column({ type: 'varchar' })
  client_name!: string

  @Column({ type: 'varchar', nullable: true })
  scope_hash!: string

  @Column({ type: 'json', default: '[]' })
  targets!: string

  @Column({ type: 'json', default: '[]' })
  modules_enabled!: string

  @Column({ type: 'varchar', default: 'normal' })
  intensity!: string

  @Column({ type: 'int', default: 60 })
  timeout_minutes!: number

  @Column({ type: 'varchar', default: 'pending' })
  status!: MissionStatus

  @Column({ type: Date, nullable: true })
  started_at!: Date | null

  @Column({ type: Date, nullable: true })
  completed_at!: Date | null

  @CreateDateColumn()
  created_at!: Date
}
