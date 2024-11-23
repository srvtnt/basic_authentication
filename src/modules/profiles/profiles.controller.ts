import { Controller, Body, Patch, Param, UseGuards } from '@nestjs/common';
import { ProfilesService } from './profiles.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth-guard';
import { UpdateProfileDto } from './dto/updateProfile.dto';
import {
  ApiBearerAuth,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@ApiBearerAuth()
@ApiUnauthorizedResponse({
  description: 'Unauthorized Bearer Token Auth',
})
@ApiTags('profile')
@Controller('profile')
export class ProfilesController {
  constructor(private readonly profilesService: ProfilesService) {}

  @UseGuards(JwtAuthGuard)
  @Patch('update/:id')
  updateProfile(
    @Param('id') id: string,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    return this.profilesService.updateProfile(id, updateProfileDto);
  }
}
