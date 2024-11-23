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
import { RolesService } from './roles.service';
import { CreateRole } from './dto/create-role.';
import { UpdateRole } from './dto/update-role.dto';
import { Auth } from '../auth/decorators/auth.decorator';
import { Role } from '../auth/types/roles.enum';
import { JwtAuthGuard } from '../auth/guards/jwt-auth-guard';
import {
  ApiBearerAuth,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@ApiBearerAuth()
@ApiUnauthorizedResponse({
  description: 'Unauthorized Bearer Token Auth',
})
@ApiTags('roles')
@Controller('roles')
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Auth(Role.ADMIN)
  @UseGuards(JwtAuthGuard)
  @Post()
  create(@Body() createRole: CreateRole) {
    return this.rolesService.create(createRole);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.rolesService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.rolesService.findOne(+id);
  }

  @Auth(Role.ADMIN)
  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  update(@Param('id') id: number, @Body() updateRole: UpdateRole) {
    return this.rolesService.update(+id, updateRole);
  }

  @Auth(Role.ADMIN)
  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.rolesService.remove(+id);
  }
}
