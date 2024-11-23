import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { CORS, envs } from './config';
import * as cookieParser from 'cookie-parser';
import {
  DocumentBuilder,
  SwaggerDocumentOptions,
  SwaggerModule,
} from '@nestjs/swagger';
import { LoginDto } from './modules/auth/dto/login.dto';

async function bootstrap() {
  const logger = new Logger('Main');
  const app = await NestFactory.create(AppModule);
  app.enableCors(CORS);
  app.setGlobalPrefix('api/v1');
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.use(cookieParser());

  //configuracion para swigger
  const config = new DocumentBuilder()
    .setTitle('DOCUMENTACION API')
    .setDescription('Documentacion de la Api para tus proyectos')
    .setVersion('1.0')
    .addBearerAuth() // Añade soporte para autenticación Bearer
    .build();

  // Opciones para el documento Swagger
  const options: SwaggerDocumentOptions = {
    extraModels: [LoginDto], // Registra DTOs adicionales
  };

  // Generar el documento Swagger
  const document = SwaggerModule.createDocument(app, config, options);

  // Configurar la interfaz de Swagger
  SwaggerModule.setup('api-docs', app, document, {
    jsonDocumentUrl: 'api-docs/json',
  });

  await app.listen(envs.port);
  logger.log(`App running on port ${envs.port}`);
}
bootstrap();
