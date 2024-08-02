import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { ConfigAuthService } from './config_auth.service';
import { UpdateConfigAuthDto } from './dto/update.dto';

@Controller('config-auth')
export class ConfigAuthController {
  constructor(private readonly configAuthService: ConfigAuthService) {}

  @Get()
  findAll() {
    return this.configAuthService.findAll();
  }

  @Patch(':id')
  update(
    @Param('id') id: string,
    @Body() updateConfigAuthDto: UpdateConfigAuthDto,
  ) {
    return this.configAuthService.update(+id, updateConfigAuthDto);
  }
}
