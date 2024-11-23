import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { encrypt, verified } from 'src/common/utils/bcryptHandle';
import { User } from './entities/user.entity';
import {
  UpdateUserPasswordByAdmin,
  UpdateUserPasswordDto,
} from './dto/updatePassword.dto';
import { UpdateUserRolDto } from './dto/updateRol.dto';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  private async findUserByCondition(condition: object): Promise<User | null> {
    try {
      return await this.prisma.user.findFirst({
        where: condition,
        include: {
          role: {
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
    } catch (error) {
      throw new HttpException(
        'Error fetching user',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  private formatUserResponse(
    user: any,
    includePassword: boolean = false,
  ): User {
    if (!user) return null;

    const response: User = {
      id: user.id,
      username: user.username,
      fullname: user.fullname,
      email: user.email,
      phone: user.phone,
      two_fa: user.two_fa,
      email_verified: user.email_verified,
      image: user.image,
      status: user.status,
      rol: user.role[0].rol,
    };

    // Incluir la contraseña solo si se solicita
    if (includePassword) {
      (response as any).password = user.password; // Agregar la contraseña al objeto de respuesta
    }

    return response;
  }

  async findUserByUsername(
    username: string,
    includePassword: boolean = false,
  ): Promise<User | null> {
    const user = await this.findUserByCondition({ username });
    return this.formatUserResponse(user, includePassword);
  }

  async findUserById(
    id: string,
    includePassword: boolean = false,
  ): Promise<User | null> {
    const user = await this.findUserByCondition({ id });
    return this.formatUserResponse(user, includePassword);
  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { username, fullname, email, phone, password, image, rol_id } =
        createUserDto;

      let findUser: User;

      if (username) {
        findUser = await this.findUserByUsername(username);
      } else if (email) {
        findUser = await this.findUserById(email);
      }

      // Check if the user already exists
      if (findUser) {
        throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
      }

      // Encrypt the password
      const hashPassword = encrypt(password);

      // Create the new user
      const newUser = await this.prisma.user.create({
        data: {
          username: username === undefined ? null : username,
          fullname,
          email: email === undefined ? null : email,
          phone,
          password: hashPassword,
          image: image ?? null, // Use null if image is undefined
          status: 'ACTIVE',
          role: { create: { rol_id } },
          profile: {
            create: {
              firstname: fullname.split(' ')[0],
              last_name: fullname.split(' ')[1] ?? '',
            },
          },
        },
        include: {
          role: {
            include: {
              rol: {
                select: { id: true, name: true },
              },
            },
          },
        },
      });

      return this.formatUserResponse(newUser);
    } catch (error) {
      throw new HttpException(
        'Error creating user',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async findAll(): Promise<User[]> {
    const users = await this.prisma.user.findMany({
      include: {
        role: {
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

    return users.map((user) => this.formatUserResponse(user));
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    return await this.prisma.user.update({
      where: { id },
      data: updateUserDto,
    });
  }

  async updatePassword(
    id: string,
    updateUserPasswordDto: UpdateUserPasswordDto,
  ): Promise<string> {
    const { new_password, confir_password } = updateUserPasswordDto;

    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.NOT_FOUND);
    }

    if (new_password !== confir_password) {
      throw new HttpException(
        'New password and confirmation do not match',
        HttpStatus.BAD_REQUEST,
      );
    }

    const hashedPassword = encrypt(new_password);

    await this.prisma.user.update({
      where: { id },
      data: { password: hashedPassword },
    });

    return 'Password updated successfully';
  }

  async updatePasswordByAdmin(
    id: string,
    updateUserPasswordByAdmin: UpdateUserPasswordByAdmin,
  ): Promise<string> {
    const { new_password, confir_password } = updateUserPasswordByAdmin;

    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.NOT_FOUND);
    }

    if (new_password !== confir_password) {
      throw new HttpException(
        'New password and confirmation do not match',
        HttpStatus.BAD_REQUEST,
      );
    }

    const hashedPassword = encrypt(new_password);

    await this.prisma.user.update({
      where: { id },
      data: { password: hashedPassword },
    });

    return 'Password updated successfully';
  }

  async remove(id: string): Promise<User> {
    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.BAD_REQUEST);
    }

    return await this.prisma.user.delete({
      where: { id },
    });
  }

  async updateRol(
    id: string,
    updateUserRolDto: UpdateUserRolDto,
  ): Promise<string> {
    const { rol_id } = updateUserRolDto;

    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.BAD_REQUEST);
    }

    const userRole = await this.prisma.userRole.findFirst({
      where: { user_id: id },
    });

    if (!userRole) {
      throw new HttpException('User role not found', HttpStatus.BAD_REQUEST);
    }

    await this.prisma.userRole.update({
      where: { id: userRole.id },
      data: { rol_id: parseInt(rol_id) },
    });

    return 'User role updated successfully';
  }
}
