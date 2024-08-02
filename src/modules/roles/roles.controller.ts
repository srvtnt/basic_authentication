import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
} from '@nestjs/common';
import { RolesService } from './roles.service';
import { CreateRole } from './dto/create-role.';
import { UpdateRole } from './dto/update-role.dto';

@Controller('roles')
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post()
  create(@Body() createRole: CreateRole) {
    return this.rolesService.create(createRole);
  }

  @Get()
  findAll() {
    return this.rolesService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.rolesService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: number, @Body() updateRole: UpdateRole) {
    return this.rolesService.update(+id, updateRole);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.rolesService.remove(+id);
  }
}
