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
      throw new HttpException('Error fetching user', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  private formatUserResponse(user: any, includePassword: boolean = false): User {
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

  async findUserByUsername(username: string,includePassword: boolean = false): Promise<User | null> {
    const user = await this.findUserByCondition({ username });
    return this.formatUserResponse(user, includePassword);
  }

  async findUserById(id: string, includePassword: boolean = false): Promise<User | null> {
    const user = await this.findUserByCondition({ id });
    return this.formatUserResponse(user, includePassword);
  }

  // async findUserByUsername(username: string): Promise<User> {
  //   try {
  //     const res = await this.prisma.user.findFirst({
  //       where: {
  //         username: username,
  //       },
  //       include: {
  //         role: {
  //           include: {
  //             rol: {
  //               select: {
  //                 id: true,
  //                 name: true,
  //               },
  //             },
  //           },
  //         },
  //       },
  //     });
  //     if (res === null) return null;

  //     const data = {
  //       id: res.id,
  //       username: res.username,
  //       fullname: res.fullname,
  //       email: res.email,
  //       phone: res.phone,
  //       password: res.password,
  //       two_fa: res.two_fa,
  //       email_verified: res.email_verified,
  //       image: res.image,
  //       status: res.status,
  //       rol: res.role[0].rol,
  //     };

  //     return data;
  //   } catch (error) {
  //     return error;
  //   }
  // }

  // async findUserById(id: string): Promise<User> {
  //   const res = await this.prisma.user.findFirst({
  //     where: {
  //       id: id,
  //     },
  //     include: {
  //       role: {
  //         include: {
  //           rol: {
  //             select: {
  //               id: true,
  //               name: true,
  //             },
  //           },
  //         },
  //       },
  //     },
  //   });
  //   if (res === null) return null;

  //   const data = {
  //     id: res.id,
  //     username: res.username,
  //     fullname: res.fullname,
  //     email: res.email,
  //     phone: res.phone,
  //     password: res.password,
  //     two_fa: res.two_fa,
  //     email_verified: res.email_verified,
  //     image: res.image,
  //     status: res.status,
  //     rol: res.role[0].rol,
  //   };

  //   return data;
  // }

  // async findOne(id: string): Promise<User> {
  //   const res = await this.prisma.user.findFirst({
  //     where: {
  //       id: id,
  //     },
  //     include: {
  //       role: {
  //         include: {
  //           rol: {
  //             select: {
  //               id: true,
  //               name: true,
  //             },
  //           },
  //         },
  //       },
  //     },
  //   });
  //   if (res === null) return null;

  //   const data = {
  //     id: res.id,
  //     username: res.username,
  //     fullname: res.fullname,
  //     email: res.email,
  //     phone: res.phone,
  //     two_fa: res.two_fa,
  //     email_verified: res.email_verified,
  //     image: res.image,
  //     status: res.status,
  //     rol: res.role[0].rol,
  //   };

  //   return data;
  // }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { username, fullname, email, phone, password, image, rol_id } = createUserDto;

      // Check if the user already exists
      const existingUser = await this.findUserByUsername(username);
      if (existingUser) {
        throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);
      }

      // Encrypt the password
      const hashPassword = encrypt(password);

      // Create the new user
      const newUser = await this.prisma.user.create({
        data: {
          username,
          fullname,
          email,
          phone,
          password: hashPassword,
          image: image ?? null, // Use null if image is undefined
          status: 'ACTIVE',
          role: { create: { rol_id } },
          profile: { create: { firstname: fullname.split(' ')[0], last_name: fullname.split(' ')[1] ?? '' } },
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
      throw new HttpException('Error creating user', HttpStatus.INTERNAL_SERVER_ERROR);
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

    return users.map(user => this.formatUserResponse(user)); 
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

  async updatePassword(id: string, updateUserPasswordDto: UpdateUserPasswordDto): Promise<string> {
    const { old_password, new_password, confir_password } = updateUserPasswordDto;
    
    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.NOT_FOUND);
    }

    if (!verified(old_password, user.password)) {
      throw new HttpException('Current password is incorrect', HttpStatus.BAD_REQUEST);
    }

    if (new_password !== confir_password) {
      throw new HttpException('New password and confirmation do not match', HttpStatus.BAD_REQUEST);
    }

    const hashedPassword = encrypt(new_password);

    await this.prisma.user.update({
      where: { id },
      data: { password: hashedPassword },
    });

    return 'Password updated successfully';
  }

  async updatePasswordByAdmin(id: string, updateUserPasswordByAdmin: UpdateUserPasswordByAdmin): Promise<string> {
    const { new_password, confir_password } = updateUserPasswordByAdmin;

    const user = await this.findUserById(id);
    if (!user) {
      throw new HttpException('User does not exist', HttpStatus.NOT_FOUND);
    }

    if (new_password !== confir_password) {
      throw new HttpException('New password and confirmation do not match', HttpStatus.BAD_REQUEST);
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

  async updateRol(id: string, updateUserRolDto: UpdateUserRolDto): Promise<string> {
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





  // async create(createUserDto: CreateUserDto): Promise<User> {
  //   try {
  //     const { username, fullname, email, phone, password, image, rol_id } =
  //       createUserDto; //destructure

  //     const names = fullname.split(' ');

  //     // I search if the user exists
  //     const resFindUser = await this.findUserByUsername(username);
  //     if (resFindUser != null)
  //       throw new HttpException('User already exists', HttpStatus.BAD_REQUEST);

  //     // I encrypt the password
  //     const hashPassword = encrypt(password);
    
  //     //create user
  //     const res = await this.prisma.user.create({
  //       data: {
  //         username: username,
  //         fullname: fullname,
  //         email: email,
  //         phone: phone,
  //         password: hashPassword,
  //         image: image === undefined ? null : image,
  //         status: 'ACTIVE',
  //         role: {
  //           create: {
  //             rol_id: rol_id,
  //           },
  //         },
  //         profile: {
  //           create: {
  //             firstname: names[0],
  //             last_name: names[1],
  //           },
  //         },
  //       },
  //       include: {
  //         role: {
  //           include: {
  //             rol: {
  //               select: {
  //                 id: true,
  //                 name: true,
  //               },
  //             },
  //           },
  //         },
  //       },
  //     });

  //     const data = {
  //       id: res.id,
  //       username: res.username,
  //       fullname: res.fullname,
  //       email: res.email,
  //       phone: res.phone,
  //       status: res.status,
  //       rol: res.role[0].rol,
  //       created_at: res.created_at,
  //     };
  //     return data;
  //   } catch (error) {
  //     return error;
  //   }
  // }

  // async findAll(): Promise<User[]> {
  //   const res: any = await this.prisma.user.findMany({
  //     include: {
  //       role: {
  //         include: {
  //           rol: {
  //             select: {
  //               id: true,
  //               name: true,
  //             },
  //           },
  //         },
  //       },
  //     },
  //   });
  //   const data = res.map((item: any) => {
  //     return {
  //       id: item.id,
  //       username: item.username,
  //       fullname: item.fullname,
  //       email: item.email,
  //       phone: item.phone,
  //       status: item.status,
  //       two_fa: item.two_fa,
  //       email_verified: item.email_verified,
  //       rol: item.role[0].rol,
  //       createdAt: item.createdAt,
  //     };
  //   });
  //   return data;
  // }

  // async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
  //   return await this.prisma.user.update({
  //     where: {
  //       id,
  //     },
  //     data: updateUserDto,
  //   });
  // }



  // async updatePassword(
  //   id: string,
  //   updateUserPasswordDto: UpdateUserPasswordDto,
  // ): Promise<string> {
  //   const { old_password, new_password, confir_password } =
  //     updateUserPasswordDto;
  //   const findUser = await this.findUserById(id);

  //   if (findUser === null)
  //     throw new HttpException('user does not exit', HttpStatus.NOT_FOUND);

  //   const passwordBD = findUser.password;
  //   const checkPassword = verified(old_password, passwordBD);

  //   if (!checkPassword)
  //     throw new HttpException(
  //       'Current password is incorrect',
  //       HttpStatus.BAD_REQUEST,
  //     );

  //   if (new_password !== confir_password)
  //     throw new HttpException(
  //       'New password and confirmation do not match',
  //       HttpStatus.BAD_REQUEST,
  //     );

  //   const hastPassword = encrypt(new_password);


  //   const res = await this.prisma.user.update({
  //     where: {
  //       id: id,
  //     },
  //     data: {
  //       password: hastPassword,
  //     },
  //   });

  //   if (res === null)
  //     throw new HttpException('could not update', HttpStatus.FORBIDDEN);

  //   return 'password updated successfully';
  // }

  // async updatePasswordByAdmin(
  //   id: string,
  //   updateUserPasswordByAdmin: UpdateUserPasswordByAdmin,
  // ): Promise<string> {
  //   const { new_password, confir_password } = updateUserPasswordByAdmin;
  //   const findUser = await this.findUserById(id);

  //   if (findUser === null)
  //     throw new HttpException('user does not exit', HttpStatus.NOT_FOUND);

  //   if (new_password !== confir_password)
  //     throw new HttpException(
  //       'New password and confirmation do not match',
  //       HttpStatus.BAD_REQUEST,
  //     );

  //   const hastPassword = encrypt(new_password);

  //   const res = await this.prisma.user.update({
  //     where: {
  //       id: id,
  //     },
  //     data: {
  //       password: hastPassword,
  //     },
  //   });

  //   if (res === null)
  //     throw new HttpException('could not update', HttpStatus.FORBIDDEN);

  //   return 'password updated successfully';
  // }

  // async remove(id: string): Promise<User> {
  //   const find = await this.findUserById(id);
  //   if (find === null)
  //     throw new HttpException('User not exists', HttpStatus.BAD_REQUEST); //If the user exists I return an error

  //   return await this.prisma.user.delete({
  //     where: {
  //       id: id,
  //     },
  //   });
  // }

  // async updateRol(
  //   id: string,
  //   updateUserRolDto: UpdateUserRolDto,
  // ): Promise<string> {
  //   const { rol_id } = updateUserRolDto;
  //   const find = await this.findUserById(id);
  //   if (find === null)
  //     throw new HttpException('User not exists', HttpStatus.BAD_REQUEST); //If the user exists I return an error

  //   const userRole = await this.prisma.userRole.findFirst({
  //     where: {
  //       user_id: id,
  //     },
  //   });

  //   if (!userRole) {
  //     throw new HttpException('User role not found', HttpStatus.BAD_REQUEST);
  //   }

  //   const res = await this.prisma.userRole.update({
  //     where: {
  //       id: userRole.id,
  //     },
  //     data: {
  //       rol_id: parseInt(rol_id),
  //     },
  //   });

  //   if (res === null)
  //     throw new HttpException(
  //       'Failed to update role to user',
  //       HttpStatus.BAD_REQUEST,
  //     ); //If the user exists I return an error

  //   return 'user role updated successfully';
  // }
}
