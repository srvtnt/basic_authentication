/*
  Warnings:

  - You are about to drop the `FailedAttempt` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "FailedAttempt" DROP CONSTRAINT "FailedAttempt_user_id_fkey";

-- DropTable
DROP TABLE "FailedAttempt";

-- CreateIndex
CREATE INDEX "AuditLog_UserAction_Index" ON "AuditLog"("user_id", "action", "timestamp");
