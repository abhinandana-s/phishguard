import { eq } from "drizzle-orm";
import { drizzle } from "drizzle-orm/mysql2";
import { InsertUser, users, urlScans } from "../drizzle/schema";
import { ENV } from './_core/env';

let _db: ReturnType<typeof drizzle> | null = null;

// Lazily create the drizzle instance so local tooling can run without a DB.
export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }

  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }

  try {
    const values: InsertUser = {
      openId: user.openId,
    };
    const updateSet: Record<string, unknown> = {};

    const textFields = ["name", "email", "loginMethod"] as const;
    type TextField = (typeof textFields)[number];

    const assignNullable = (field: TextField) => {
      const value = user[field];
      if (value === undefined) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };

    textFields.forEach(assignNullable);

    if (user.lastSignedIn !== undefined) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== undefined) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = 'admin';
      updateSet.role = 'admin';
    }

    if (!values.lastSignedIn) {
      values.lastSignedIn = new Date();
    }

    if (Object.keys(updateSet).length === 0) {
      updateSet.lastSignedIn = new Date();
    }

    await db.insert(users).values(values).onDuplicateKeyUpdate({
      set: updateSet,
    });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot get user: database not available");
    return undefined;
  }

  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);

  return result.length > 0 ? result[0] : undefined;
}

export async function createUrlScan(
  userId: number,
  url: string,
  threatLevel: "safe" | "suspicious" | "dangerous",
  riskScore: number,
  reasons: string[],
  triggeredRules: Array<{ id: string; name: string; description: string; weight: number }>
) {
  const db = await getDb();
  if (!db) {
    throw new Error("Database not available");
  }

  await db.insert(urlScans).values({
    userId,
    url,
    threatLevel,
    riskScore,
    reasons: JSON.stringify(reasons),
    triggeredRules: JSON.stringify(triggeredRules),
  });
}

export async function getUserUrlScans(
  userId: number,
  limit: number = 50,
  offset: number = 0
) {
  const db = await getDb();
  if (!db) {
    throw new Error("Database not available");
  }

  const scans = await db
    .select()
    .from(urlScans)
    .where(eq(urlScans.userId, userId))
    .orderBy(urlScans.createdAt)
    .limit(limit)
    .offset(offset);

  return scans.map((scan) => ({
    ...scan,
    reasons: JSON.parse(scan.reasons),
    triggeredRules: JSON.parse(scan.triggeredRules),
  }));
}

export async function getUrlScanById(scanId: number) {
  const db = await getDb();
  if (!db) {
    throw new Error("Database not available");
  }

  const scan = await db.select().from(urlScans).where(eq(urlScans.id, scanId)).limit(1);
  if (scan.length === 0) return null;

  const result = scan[0];
  return {
    ...result,
    reasons: JSON.parse(result.reasons),
    triggeredRules: JSON.parse(result.triggeredRules),
  };
}
