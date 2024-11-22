import {  Injectable } from '@nestjs/common';
import { PrismaService } from 'src/common/prisma/prisma.service';
import { Profile } from './entities/profile.entity';
import { UpdateProfileDto } from './dto/updateProfile.dto';

@Injectable()
export class ProfilesService {
  constructor(
    private readonly prisma: PrismaService,
  ) {}

  async updateProfile(
    id: string,
    updateUserProfileDto: UpdateProfileDto,
  ): Promise<Profile> {
    return await this.prisma.profile.update({
      where: {
        user_id: id,
      },
      data: updateUserProfileDto,
    });
  }

 
 

 
}
