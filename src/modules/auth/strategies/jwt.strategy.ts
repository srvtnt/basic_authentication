import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { envs } from 'src/config';
import { PrismaService } from 'src/common/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly prisma: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: envs.jwtSecret,
    });
  }

  async validate(payload: any) {
    // Verifica si el usuario existe en la base de datos
    const user = await this.prisma.users.findUnique({
      where: { id: payload.id },
      include: {
        roles: {
          select: {
            id: true,
          },
        },
      },
    });

    // Si el usuario no existe, lanza una excepción
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Devuelve los datos del usuario
    return {
      userId: user.id,
      email: user.email,
      role: user.roles[0].id,
      expire_in: payload.exp,
    };
  }
}
