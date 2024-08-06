export interface OutputConfigAuth {
  id: number;
  https: boolean;
  useEmail?: boolean;
  max_last_pass: number;
  time_life_pass: number;
  twoFA?: boolean;
  time_life_code: number;
  createdAt?: Date;
  updatedAt?: Date;
}
