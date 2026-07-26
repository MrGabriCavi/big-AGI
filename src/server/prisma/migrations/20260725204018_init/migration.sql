-- CreateEnum
CREATE TYPE "LinkStorageVisibility" AS ENUM ('PUBLIC', 'UNLISTED', 'PRIVATE');

-- CreateEnum
CREATE TYPE "LinkStorageDataType" AS ENUM ('CHAT_V1');

-- CreateTable
CREATE TABLE "LinkStorage" (
    "id" TEXT NOT NULL,
    "ownerId" TEXT NOT NULL,
    "visibility" "LinkStorageVisibility" NOT NULL,
    "dataType" "LinkStorageDataType" NOT NULL,
    "dataTitle" TEXT,
    "dataSize" INTEGER NOT NULL,
    "data" JSONB NOT NULL,
    "upVotes" INTEGER NOT NULL DEFAULT 0,
    "downVotes" INTEGER NOT NULL DEFAULT 0,
    "flagsCount" INTEGER NOT NULL DEFAULT 0,
    "readCount" INTEGER NOT NULL DEFAULT 0,
    "writeCount" INTEGER NOT NULL DEFAULT 1,
    "expiresAt" TIMESTAMP(3),
    "deletionKey" TEXT NOT NULL,
    "isDeleted" BOOLEAN NOT NULL DEFAULT false,
    "deletedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LinkStorage_pkey" PRIMARY KEY ("id")
);
