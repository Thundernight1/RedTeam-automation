import { AppDataSource } from './data-source.js';

// PostgreSQL query helper using TypeORM
export const query = async (sql: string, params?: unknown[]) => {
  const queryRunner = AppDataSource.createQueryRunner();
  try {
    await queryRunner.connect();
    const result = await queryRunner.query(sql, params);
    return { rows: result };
  } catch (error) {
    // If database is not initialized, return empty result
    if (!AppDataSource.isInitialized) {
      return { rows: [] };
    }
    throw error;
  } finally {
    await queryRunner.release();
  }
};

// TypeORM repository helper
export const getRepository = <T>(entity: new () => T) => {
  if (!AppDataSource.isInitialized) {
    throw new Error('DataSource not initialized. Call initializeDatabase() first.');
  }
  return AppDataSource.getRepository(entity);
};

export { AppDataSource };
