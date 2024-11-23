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
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Auth } from '../auth/decorators/auth.decorator';
import { Role } from '../auth/types/roles.enum';
import { JwtAuthGuard } from '../auth/guards/jwt-auth-guard';
import {
  UpdateUserPasswordByAdmin,
  UpdateUserPasswordDto,
} from './dto/updatePassword.dto';
import { UpdateUserRolDto } from './dto/updateRol.dto';
import {
  ApiBearerAuth,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';

@ApiBearerAuth()
@ApiUnauthorizedResponse({
  description: 'Unauthorized Bearer Token Auth',
})
@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Auth(Role.ADMIN)
  @Post('create')
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('findAll')
  findAll() {
    return this.usersService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get('findOne/:id')
  findOne(@Param('id') id: string) {
    return this.usersService.findUserById(id);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('update/:id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('update_password/:id')
  updatePassword(
    @Param('id') id: string,
    @Body() updateUserPasswordDto: UpdateUserPasswordDto,
  ) {
    return this.usersService.updatePassword(id, updateUserPasswordDto);
  }

  @UseGuards(JwtAuthGuard)
  @Auth(Role.ADMIN)
  @Patch('update_password_byadmin/:id')
  updatePasswordByAdmin(
    @Param('id') id: string,
    @Body() updateUserPasswordByAdmin: UpdateUserPasswordByAdmin,
  ) {
    return this.usersService.updatePasswordByAdmin(
      id,
      updateUserPasswordByAdmin,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Auth(Role.ADMIN)
  @Delete('delete/:id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }

  @UseGuards(JwtAuthGuard)
  @Auth(Role.ADMIN)
  @Patch('update_rol/:id')
  update_rol(
    @Param('id') id: string,
    @Body() updateUserRolDto: UpdateUserRolDto,
  ) {
    return this.usersService.updateRol(id, updateUserRolDto);
  }
}
