import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateRole } from './dto/create-role.';
import { UpdateRole } from './dto/update-role.dto';
import { Roles } from './entities/role.entity';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { OutputRoles } from './types';

@Injectable()
export class RolesService {
  constructor(private prismaService: PrismaService) {}

  async findRolName(name: string): Promise<Roles> {
    return await this.prismaService.roles.findFirst({
      where: {
        name: name,
      },
    });
  }

  async findRolId(id: number): Promise<Roles> {
    return await this.prismaService.roles.findFirst({
      where: {
        id: id,
      },
    });
  }

  async create(createRole: CreateRole): Promise<OutputRoles> {
    const { name, description } = createRole;
    const find = await this.findRolName(name);
    if (find != null)
      throw new HttpException('rol already exists', HttpStatus.BAD_REQUEST);
    const res: any = await this.prismaService.roles.create({
      data: {
        name: name.toLocaleUpperCase(),
        description: description.toLocaleUpperCase(),
      },
    });
    return {
      id: res.id,
      name: res.name,
      description: res.description,
    };
  }

  async findAll(): Promise<OutputRoles[]> {
    const res = await this.prismaService.roles.findMany();
    const data = res.map((item) => {
      return {
        id: item.id,
        name: item.name,
        description: item.description,
      };
    });
    return data;
  }

  async findOne(id: number): Promise<OutputRoles> {
    const res = await this.findRolId(id);
    if (res === null)
      throw new HttpException('rol does not exist', HttpStatus.BAD_REQUEST);
    return {
      id: res.id,
      name: res.name,
      description: res.description,
    };
  }

  async update(id: number, updateRole: UpdateRole): Promise<OutputRoles> {
    const { name, description } = updateRole;
    const find = await this.findRolId(id);

    if (find === null)
      throw new HttpException(
        'cannot update category does not exist',
        HttpStatus.BAD_REQUEST,
      );
    const res: any = await this.prismaService.roles.update({
      where: {
        id: id,
      },
      data: {
        name: name,
        description: description,
      },
    });
    return {
      id: res.id,
      name: res.name,
      description: res.description,
    };
  }

  async remove(id: number): Promise<OutputRoles> {
    const find = await this.findRolId(id);
    if (find === null)
      throw new HttpException(
        'cannot delete rol does not exist',
        HttpStatus.BAD_REQUEST,
      );
    const res: any = await this.prismaService.roles.delete({
      where: {
        id: id,
      },
    });

    return {
      id: res.id,
      name: res.name,
      description: res.description,
    };
  }
}
