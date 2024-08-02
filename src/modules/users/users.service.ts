import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { ConfigAuthService } from '../config_auth/config_auth.service';
import { encrypt } from 'src/common/utils/bcryptHandle';
import { getExpiry } from 'src/common/utils/dateTimeUtility';

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configAuthService: ConfigAuthService,
  ) {}

  async findUserByUsername(username: string) {
    try {
      const res = await this.prisma.users.findFirst({
        where: {
          username: username,
        },
        include: {
          roles: {
            include: {
              rol: {
                select: {
                  id: true,
                  name: true,
                },
              },
            },
          },
        },
      });
      if (res === null) return null;

      const data = {
        id: res.id,
        username: res.username,
        fullname: res.fullname,
        email: res.email,
        phone: res.phone,
        password: res.password,
        lastpass: res.lastpass,
        expirepass: res.expirepass,
        force_new_pass: res.force_new_pass,
        twoFA: res.twoFA,
        isEmailVerified: res.isEmailVerified,
        status: res.status,
        rol: res.roles[0].rol,
      };

      return data;
    } catch (error) {
      return error;
    }
  }

  async create(createUserDto: CreateUserDto) {
    try {
      const {
        username,
        fullname,
        email,
        phone,
        password,
        force_new_pass,
        rol_id,
      } = createUserDto; //destructure

      const findConfigAuth = await this.configAuthService.findAll(); //look for the general auth configuration
      const names = fullname.split(' ');

      // I search if the user exists
      const resFindUser = await this.findUserByUsername(username);
      if (resFindUser != null)
        throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);

      // I encrypt the password
      const hashPassword = encrypt(password);
      const expirePass = getExpiry(findConfigAuth.time_life_pass);

      //create user
      const res = await this.prisma.users.create({
        data: {
          username: username,
          fullname: fullname,
          email: email,
          phone: phone,
          password: hashPassword,
          lastpass: [`${hashPassword}`],
          expirepass: expirePass,
          force_new_pass: force_new_pass,
          status: 'ACTIVE',
          roles: {
            create: {
              rol_id: rol_id,
            },
          },
          profile: {
            create: {
              firstname: names[0],
              last_name: names[1],
            },
          },
        },
        include: {
          roles: {
            include: {
              rol: {
                select: {
                  id: true,
                  name: true,
                },
              },
            },
          },
        },
      });

      const data = {
        id: res.id,
        username: res.username,
        fullname: res.fullname,
        email: res.email,
        phone: res.phone,
        status: res.status,
        rol: res.roles[0].rol,
        createdAt: res.created_at,
      };
      return data;
    } catch (error) {
      return error;
    }
  }

  async findAll() {
    const res: any = await this.prisma.users.findMany({
      include: {
        roles: {
          include: {
            rol: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        },
      },
    });
    const data = res.map((item: any) => {
      return {
        id: item.id,
        username: item.username,
        fullname: item.fullname,
        email: item.email,
        phone: item.phone,
        status: item.status,
        rol: item.roles[0].rol,
      };
    });
    return data;
  }

  async findUserById(id: string) {
    const res = await this.prisma.users.findFirst({
      where: {
        id: id,
      },
      include: {
        roles: {
          include: {
            rol: {
              select: {
                id: true,
                name: true,
              },
            },
          },
        },
      },
    });
    if (res === null) return null;

    const data = {
      id: res.id,
      username: res.username,
      fullname: res.fullname,
      email: res.email,
      phone: res.phone,
      password: res.password,
      lastpass: res.lastpass,
      expirepass: res.expirepass,
      force_new_pass: res.force_new_pass,
      twoFA: res.twoFA,
      isEmailVerified: res.isEmailVerified,
      status: res.status,
      rol: res.roles[0].rol,
    };

    return data;
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    const res = await this.prisma.users.update({
      where: {
        id,
      },
      data: updateUserDto,
    });
    return res;
  }

  async remove(id: string) {
    const find = await this.findUserById(id);
    if (find === null)
      throw new HttpException('User not exists', HttpStatus.BAD_REQUEST); //If the user exists I return an error

    return await this.prisma.users.delete({
      where: {
        id: id,
      },
    });
  }
}
