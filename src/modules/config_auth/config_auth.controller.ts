import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  UseGuards,
} from '@nestjs/common';
import { ConfigAuthService } from './config_auth.service';
import { UpdateConfigAuthDto } from './dto/update.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth-guard';
import { Auth } from '../auth/decorators/auth.decorator';
import { Role } from '../auth/types/roles.enum';

@Controller('config-auth')
export class ConfigAuthController {
  constructor(private readonly configAuthService: ConfigAuthService) {}

  @Auth(Role.ADMIN)
  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.configAuthService.findAll();
  }

  @Auth(Role.ADMIN)
  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateConfigAuthDto: UpdateConfigAuthDto,
  ) {
    return this.configAuthService.update(+id, updateConfigAuthDto);
  }
}
