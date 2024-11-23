-- CreateTable
CREATE TABLE "FailedAttempt" (
    "user_id" UUID NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "FailedAttempt_pkey" PRIMARY KEY ("user_id")
);

-- AddForeignKey
ALTER TABLE "FailedAttempt" ADD CONSTRAINT "FailedAttempt_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
