import { hashSync, compareSync } from 'bcrypt';
const encrypt = (pass: string) => {
  const passwordHash = hashSync(pass, 10);
  return passwordHash;
};

const verified = (pass: string, passHash: string) => {
  const isCorrerct = compareSync(pass, passHash);
  return isCorrerct;
};

export { encrypt, verified };
