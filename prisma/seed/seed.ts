import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
const prisma = new PrismaClient();

async function main() {
  const password = 'admin123';
  const hashPassword = await bcrypt.hash(password, 10);
  const roles = await prisma.role.createMany({
    data: [
      { name: 'admin', description: 'role with all privileges' },
      { name: 'user', description: 'default role' },
    ],
  });

  const user = await prisma.user.create({
    data: {
      username: 'admin',
      fullname: 'Administrador',
      email: 'admin@example.com',
      phone: '0212000000',
      password: hashPassword,
      email_verified: new Date(),
      status: 'ACTIVE',
      role: {
        create: {
          rol_id: 1,
        },
      },
      profile: {
        create: {
          firstname: 'Administrador',
          last_name: 'Sistema',
        },
      },
    },
  });
  console.log({ roles, user });
}
main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
