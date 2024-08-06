import { Resend } from 'resend';
import { envs } from 'src/config';

const resend = new Resend(envs.apyKeyResend);

export const sendMail = async (
  from: string,
  to: string[],
  subject: string,
  html: string,
) => {
  const { data, error } = await resend.emails.send({
    from: from,
    to: to,
    subject: subject,
    html: `${html}`,
  });

  if (error) {
    return error;
  }

  return data;
};
