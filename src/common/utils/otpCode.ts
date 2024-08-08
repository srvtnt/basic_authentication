export const generateOTP = (): number => {
  const digits = '0123456789';
  let otp = '';

  for (let i = 0; i < 6; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }

  return parseInt(otp, 10); // Convertir la cadena a número
};
