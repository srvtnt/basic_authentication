import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { ConfigAuthService } from '../config_auth/config_auth.service';
import { encrypt, verified } from 'src/common/utils/bcryptHandle';
import { getExpiry } from 'src/common/utils/dateTimeUtility';
import { Users } from './entities/user.entity';
import { UpdateUserProfileDto } from './dto/updateProfile.dto';
import {
  UpdateUserPasswordByAdmin,
  UpdateUserPasswordDto,
} from './dto/updatePassword.dto';
import { ProfileDB } from './types';
import { UpdateUserRolDto } from './dto/updateRol.dto';

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configAuthService: ConfigAuthService,
  ) {}

  async findUserByUsername(username: string): Promise<Users> {
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

  async findUserById(id: string): Promise<Users> {
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

  async findOne(id: string): Promise<Users> {
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
      twoFA: res.twoFA,
      isEmailVerified: res.isEmailVerified,
      status: res.status,
      rol: res.roles[0].rol,
    };

    return data;
  }

  async create(createUserDto: CreateUserDto): Promise<Users> {
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
          force_new_pass: force_new_pass === undefined ? false : force_new_pass,
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
        createdAt: res.createdAt,
      };
      return data;
    } catch (error) {
      return error;
    }
  }

  async findAll(): Promise<Users[]> {
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
        createdAt: item.createdAt,
      };
    });
    return data;
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<Users> {
    return await this.prisma.users.update({
      where: {
        id,
      },
      data: updateUserDto,
    });
  }

  async updateProfile(
    id: string,
    updateUserProfileDto: UpdateUserProfileDto,
  ): Promise<ProfileDB> {
    return await this.prisma.profile.update({
      where: {
        userId: id,
      },
      data: updateUserProfileDto,
    });
  }

  async updatePassword(
    id: string,
    updateUserPasswordDto: UpdateUserPasswordDto,
  ): Promise<string> {
    const { old_password, new_password, confir_password } =
      updateUserPasswordDto;
    const findUser = await this.findUserById(id);

    if (findUser === null)
      throw new HttpException('user does not exit', HttpStatus.NOT_FOUND);

    const lastpass = findUser.lastpass;
    const passwordBD = findUser.password;
    const checkPassword = verified(old_password, passwordBD);

    if (!checkPassword)
      throw new HttpException(
        'Current password is incorrect',
        HttpStatus.BAD_REQUEST,
      );

    const verifyLastPass = lastpass.some((item: any) => {
      const verifiedPass = verified(new_password, item);
      return verifiedPass;
    });

    if (verifyLastPass)
      throw new HttpException(
        'The new password matches the last three',
        HttpStatus.FORBIDDEN,
      );

    if (new_password !== confir_password)
      throw new HttpException(
        'New password and confirmation do not match',
        HttpStatus.BAD_REQUEST,
      );

    const hastPassword = encrypt(new_password);

    if (lastpass.length === 3) {
      // Eliminar el último registro insertado
      lastpass.shift();
      lastpass.push(hastPassword);
    } else {
      lastpass.push(hastPassword);
    }

    const res = await this.prisma.users.update({
      where: {
        id: id,
      },
      data: {
        password: hastPassword,
        lastpass: lastpass,
      },
    });

    if (res === null)
      throw new HttpException('could not update', HttpStatus.FORBIDDEN);

    return 'password updated successfully';
  }

  async updatePasswordByAdmin(
    id: string,
    updateUserPasswordByAdmin: UpdateUserPasswordByAdmin,
  ): Promise<string> {
    const { new_password, confir_password } = updateUserPasswordByAdmin;
    const findUser = await this.findUserById(id);

    if (findUser === null)
      throw new HttpException('user does not exit', HttpStatus.NOT_FOUND);

    const lastpass = findUser.lastpass;

    const verifyLastPass = lastpass.some((item: any) => {
      const verifiedPass = verified(new_password, item);
      return verifiedPass;
    });

    if (verifyLastPass)
      throw new HttpException(
        'The new password matches the last three',
        HttpStatus.FORBIDDEN,
      );

    if (new_password !== confir_password)
      throw new HttpException(
        'New password and confirmation do not match',
        HttpStatus.BAD_REQUEST,
      );

    const hastPassword = encrypt(new_password);

    if (lastpass.length === 3) {
      // Eliminar el último registro insertado
      lastpass.shift();
      lastpass.push(hastPassword);
    } else {
      lastpass.push(hastPassword);
    }

    const res = await this.prisma.users.update({
      where: {
        id: id,
      },
      data: {
        password: hastPassword,
        lastpass: lastpass,
      },
    });

    if (res === null)
      throw new HttpException('could not update', HttpStatus.FORBIDDEN);

    return 'password updated successfully';
  }

  async remove(id: string): Promise<Users> {
    const find = await this.findUserById(id);
    if (find === null)
      throw new HttpException('User not exists', HttpStatus.BAD_REQUEST); //If the user exists I return an error

    return await this.prisma.users.delete({
      where: {
        id: id,
      },
    });
  }

  async updateRol(
    id: string,
    updateUserRolDto: UpdateUserRolDto,
  ): Promise<string> {
    const { rol_id } = updateUserRolDto;
    const find = await this.findUserById(id);
    if (find === null)
      throw new HttpException('User not exists', HttpStatus.BAD_REQUEST); //If the user exists I return an error

    const userRole = await this.prisma.users_roles.findFirst({
      where: {
        user_id: id,
      },
    });

    if (!userRole) {
      throw new HttpException('User role not found', HttpStatus.BAD_REQUEST);
    }

    const res = await this.prisma.users_roles.update({
      where: {
        id: userRole.id,
      },
      data: {
        rol_id: parseInt(rol_id),
      },
    });

    if (res === null)
      throw new HttpException(
        'Failed to update role to user',
        HttpStatus.BAD_REQUEST,
      ); //If the user exists I return an error

    return 'user role updated successfully';
  }
}
