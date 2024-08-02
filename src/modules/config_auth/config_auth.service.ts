import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { UpdateConfigAuthDto } from './dto/update.dto';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { OutputConfigAuth } from './types/config';

@Injectable()
export class ConfigAuthService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(): Promise<OutputConfigAuth> {
    try {
      const res = await this.prisma.config_auth.findMany();
      return {
        id: res[0].id,
        https: res[0].https,
        max_last_pass: res[0].max_last_pass,
        time_life_pass: res[0].time_life_pass,
        twoFA: res[0].twoFA,
        time_life_code: res[0].time_life_code,
      };
    } catch (error) {
      return error;
    }
  }

  async findConfigById(id: number) {
    try {
      const res = await this.prisma.config_auth.findFirst({
        where: {
          id: id,
        },
      });
      return res;
    } catch (error) {
      return error;
    }
  }
  async update(id: number, updateConfigAuthDto: UpdateConfigAuthDto) {
    const { ...data } = updateConfigAuthDto;
    const findConfig = await this.findConfigById(id);

    if (!findConfig)
      throw new HttpException('Error config not exist', HttpStatus.BAD_REQUEST);
    const res = await this.prisma.config_auth.update({
      where: {
        id: id,
      },
      data: data,
    });
    return res;
  }
}
