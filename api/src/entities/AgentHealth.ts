import { Entity, PrimaryColumn, Column } from 'typeorm'

@Entity('agent_health')
export class AgentHealth {
  @PrimaryColumn('varchar')
  agent_id!: string

  @Column({ type: 'varchar' })
  agent_type!: string

  @Column({ type: 'varchar', default: 'unknown' })
  status!: string

  @Column({ type: Date, nullable: true })
  last_heartbeat!: Date | null

  @Column({ type: 'int', default: 0 })
  tasks_completed!: number

  @Column({ type: 'int', default: 0 })
  tasks_failed!: number

  @Column({ type: 'varchar', nullable: true })
  hostname!: string
}
