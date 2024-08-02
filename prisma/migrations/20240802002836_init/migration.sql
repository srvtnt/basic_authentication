-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- CreateEnum
CREATE TYPE "UseCase" AS ENUM ('PASS', 'D2FA', 'E2FA', 'VEM');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "username" TEXT NOT NULL,
    "fullname" TEXT,
    "email" TEXT NOT NULL,
    "phone" TEXT,
    "password" TEXT NOT NULL,
    "metadata" JSONB,
    "lastpass" JSONB,
    "expirepass" TIMESTAMP(3),
    "force_new_pass" BOOLEAN DEFAULT false,
    "twoFA" BOOLEAN DEFAULT false,
    "isEmailVerified" BOOLEAN DEFAULT false,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "profile" (
    "id" SERIAL NOT NULL,
    "userId" UUID NOT NULL,
    "firstname" TEXT NOT NULL,
    "second_name" TEXT,
    "last_name" TEXT NOT NULL,
    "second_surname" TEXT,
    "birthday" TIMESTAMP(3),
    "gender" TEXT,
    "phone" TEXT,
    "metadata" JSONB,
    "localityId" INTEGER,
    "picture" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "profile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "roles" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "users_roles" (
    "id" SERIAL NOT NULL,
    "user_id" UUID NOT NULL,
    "rol_id" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "users_roles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "verification_tokens" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "useCase" "UseCase" NOT NULL,
    "jwt" TEXT NOT NULL,
    "code" INTEGER,
    "userId" UUID NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expireAt" TIMESTAMP(3) NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "verification_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "config_auth" (
    "id" SERIAL NOT NULL,
    "https" BOOLEAN,
    "useEmail" BOOLEAN,
    "max_last_pass" INTEGER,
    "time_life_pass" INTEGER,
    "twoFA" BOOLEAN,
    "time_life_code" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "config_auth_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions_auth" (
    "id" SERIAL NOT NULL,
    "userId" UUID NOT NULL,
    "jwt" TEXT NOT NULL,
    "expireAt" INTEGER NOT NULL,
    "last_activity" TIMESTAMP(3),
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sessions_auth_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_username_key" ON "users"("username");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "User_Index_00" ON "users"("username", "email");

-- CreateIndex
CREATE UNIQUE INDEX "profile_userId_key" ON "profile"("userId");

-- CreateIndex
CREATE INDEX "Profile_Index_00" ON "profile"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "roles_name_key" ON "roles"("name");

-- CreateIndex
CREATE INDEX "Roles_Index_00" ON "roles"("name");

-- CreateIndex
CREATE INDEX "User_Roles_Index_00" ON "users_roles"("user_id", "rol_id");

-- CreateIndex
CREATE UNIQUE INDEX "verification_tokens_jwt_key" ON "verification_tokens"("jwt");

-- CreateIndex
CREATE INDEX "Service_token_Index_00" ON "verification_tokens"("jwt");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_auth_jwt_key" ON "sessions_auth"("jwt");

-- AddForeignKey
ALTER TABLE "profile" ADD CONSTRAINT "profile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "users_roles" ADD CONSTRAINT "users_roles_rol_id_fkey" FOREIGN KEY ("rol_id") REFERENCES "roles"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "users_roles" ADD CONSTRAINT "users_roles_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "verification_tokens" ADD CONSTRAINT "verification_tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions_auth" ADD CONSTRAINT "sessions_auth_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
