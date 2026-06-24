import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm'

@Entity('scope_agreements')
export class ScopeAgreement {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  client_name!: string

  @Column({ type: 'json' })
  authorized_targets!: string

  @Column({ type: 'json', default: '[]' })
  excluded_targets!: string

  @Column({ type: Date })
  valid_from!: Date

  @Column({ type: Date })
  valid_until!: Date

  @Column({ type: 'varchar' })
  authorized_by!: string

  @Column({ type: 'varchar', nullable: true })
  scope_hash!: string

  @CreateDateColumn()
  created_at!: Date
}
