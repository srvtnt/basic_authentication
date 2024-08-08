import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { CreateRole } from './dto/create-role.';
import { UpdateRole } from './dto/update-role.dto';
import { Role } from './entities/role.entity';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { OutputRole } from './types';

@Injectable()
export class RolesService {
  constructor(private prismaService: PrismaService) {}

  async findRolName(name: string): Promise<Role> {
    return await this.prismaService.role.findFirst({
      where: {
        name: name,
      },
    });
  }

  async findRolId(id: number): Promise<Role> {
    return await this.prismaService.role.findFirst({
      where: {
        id: id,
      },
    });
  }

  async create(createRole: CreateRole): Promise<OutputRole> {
    const { name, description } = createRole;
    const find = await this.findRolName(name);
    if (find != null)
      throw new HttpException('rol already exists', HttpStatus.BAD_REQUEST);
    const res: any = await this.prismaService.role.create({
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

  async findAll(): Promise<OutputRole[]> {
    const res = await this.prismaService.role.findMany();
    const data = res.map((item) => {
      return {
        id: item.id,
        name: item.name,
        description: item.description,
      };
    });
    return data;
  }

  async findOne(id: number): Promise<OutputRole> {
    const res = await this.findRolId(id);
    if (res === null)
      throw new HttpException('rol does not exist', HttpStatus.BAD_REQUEST);
    return {
      id: res.id,
      name: res.name,
      description: res.description,
    };
  }

  async update(id: number, updateRole: UpdateRole): Promise<OutputRole> {
    const { name, description } = updateRole;
    const find = await this.findRolId(id);

    if (find === null)
      throw new HttpException(
        'cannot update category does not exist',
        HttpStatus.BAD_REQUEST,
      );
    const res: any = await this.prismaService.role.update({
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

  async remove(id: number): Promise<OutputRole> {
    const find = await this.findRolId(id);
    if (find === null)
      throw new HttpException(
        'cannot delete rol does not exist',
        HttpStatus.BAD_REQUEST,
      );
    const res: any = await this.prismaService.role.delete({
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
