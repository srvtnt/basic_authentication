import { PartialType } from '@nestjs/mapped-types';
import { CreateRole } from './create-role.';
export class UpdateRole extends PartialType(CreateRole) {}
