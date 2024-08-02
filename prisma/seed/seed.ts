import { PrismaClient } from '@prisma/client';
import * as moment from 'moment';
import * as bcrypt from 'bcrypt';
const prisma = new PrismaClient();

const getExpiry = (cant: number) => {
  const createdAt = new Date();
  const expiresAt = moment(createdAt).add(cant, 'days').toDate();
  return expiresAt;
};

async function main() {
  const expire_pass = getExpiry(365);
  const password = 'admin123';
  const hashPassword = await bcrypt.hash(password, 10);
  const roles = await prisma.roles.createMany({
    data: [
      { name: 'admin', description: 'role with all privileges' },
      { name: 'user', description: 'default role' },
    ],
  });

  const user = await prisma.users.create({
    data: {
      username: 'admin',
      fullname: 'Administrador',
      email: 'admin@example.com',
      phone: '0212000000',
      password: hashPassword,
      lastpass: [hashPassword],
      expirepass: expire_pass,
      force_new_pass: false,
      roles: {
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

  const config = await prisma.config_auth.create({
    data: {
      https: false,
      useEmail: false,
      max_last_pass: 3,
      time_life_pass: 90,
      twoFA: false,
      time_life_code: 900,
    },
  });
  console.log({ roles, user, config });
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
