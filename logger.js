import 'dotenv/config';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import fs from 'fs';

const LOG_DIR = process.env.LOG_DIR || './logs';
fs.mkdirSync(LOG_DIR, { recursive: true });

const formatter = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(info => `[${info.timestamp}] ${info.level.toUpperCase()} ${info.message}`)
);

export const logger = winston.createLogger({
  level: 'info',
  format: formatter,
  transports: [
    new DailyRotateFile({ dirname: LOG_DIR, filename: 'server-%DATE%.log', datePattern: 'YYYY-MM-DD', maxFiles: '14d' }),
    new DailyRotateFile({ dirname: LOG_DIR, filename: 'error-%DATE%.log', datePattern: 'YYYY-MM-DD', level: 'error', maxFiles: '30d' }),
    new winston.transports.Console()
  ]
});
