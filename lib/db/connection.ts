import { MongoClient, Db } from 'mongodb';

/**
 * MongoDB connection handler using singleton pattern
 * Ensures single database connection across the application
 */

if (!process.env.MONGODB_URI) {
  throw new Error('MONGODB_URI environment variable is not defined');
}

const MONGODB_URI: string = process.env.MONGODB_URI;
const options = {};

let cachedClient: MongoClient | null = null;
let cachedDb: Db | null = null;

/**
 * Connect to MongoDB and return database instance
 * Uses connection pooling and caching for efficiency
 */
export async function connectToDatabase(): Promise<{ client: MongoClient; db: Db }> {
  // Return cached connection if available
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  try {
    // Create new connection
    const client = await MongoClient.connect(MONGODB_URI, options);
    const db = client.db();

    // Cache the connection
    cachedClient = client;
    cachedDb = db;

    console.log('✅ Connected to MongoDB');

    return { client, db };
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    throw new Error('Failed to connect to database');
  }
}

/**
 * Get database instance (throws if not connected)
 */
export async function getDatabase(): Promise<Db> {
  const { db } = await connectToDatabase();
  return db;
}
