/**
 * ApiKey entity for storing platform API credentials (HackerOne, Bugcrowd, etc.)
 */
import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, Index, JoinColumn } from 'typeorm'
import { User } from './User.js'

@Entity('api_keys')
@Index(['user_id', 'is_active'])
@Index(['name'])
export class ApiKey {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'varchar' })
  user_id!: string

  @Column({ type: 'varchar' })
  name!: string

  @Column({ type: 'text' })
  key_preview!: string

  @Column({ type: 'text' })
  key_hash!: string

  @Column({ type: 'json', nullable: true })
  permissions!: Record<string, boolean>

  @Column({ type: 'boolean', default: true })
  is_active!: boolean

  @Column({ type: Date, nullable: true })
  last_used_at!: Date

  @Column({ type: Date, nullable: true })
  expires_at!: Date

  @CreateDateColumn()
  created_at!: Date

  @UpdateDateColumn()
  updated_at!: Date

  @ManyToOne(() => User)
  @JoinColumn({ name: 'user_id' })
  user!: User

  isExpired(): boolean {
    if (!this.expires_at) return false
    return new Date() > this.expires_at
  }

  isValid(): boolean {
    return this.is_active && !this.isExpired()
  }
}
