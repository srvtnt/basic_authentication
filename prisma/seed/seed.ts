import { PrismaClient } from '@prisma/client';
// import { encrypt } from "../../src/utils/bcrypt.handle";
const prisma = new PrismaClient();
async function main() {
  const password = 'admin123';
  // const hashPassword = encrypt(password);
  const roles = await prisma.roles.createMany({
    data: [
      { name: 'administrador', description: 'rol administrador' },
      { name: 'autoridad', description: 'rol para las autoridades' },
      { name: 'director', description: 'rol para los directores' },
      { name: 'usuario', description: 'rol por defecto' },
    ],
  });

  const user = await prisma.users.create({
    data: {
      username: 'admin',
      fullname: 'Administrador',
      email: 'admin@example.com',
      phone: '0212000000',
      // password: hashPassword,
      // lastpass: [hashPassword],
      expirepass: new Date(),
      force_new_pass: false,
      rol: {
        create: {
          rol_id: 1,
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
