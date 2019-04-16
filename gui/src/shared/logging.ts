/* tslint:disable:no-console */

import { ipcMain, ipcRenderer } from 'electron';
import * as fs from 'fs';
import * as path from 'path';
import { sprintf, vsprintf } from 'sprintf-js';
import { promisify } from 'util';

const fsOpen = promisify(fs.open);
const fsWrite = promisify(fs.write);
const fsAccess = promisify(fs.access);
const fsRename = promisify(fs.rename);

const DEFAULT_LOG_FORMAT = '[%(year)d-%(month)02d-%(day)02d %(hour)02d:%(minute)02d:%(seconds)02d.%(millis)03d][%(level)s] %(message)s';
const DEFAULT_IPC_LOGGER = 'DEFAULT_IPC_LOGGER';

export enum LogLevel {
  warn,
  info,
  error,
  debug,
}

export interface ILogger {
  write(level: LogLevel, message: string): void;
}

export class Log {
  public transports: ILogger[] = [];

  public warn(format: string, ...args: any[]) {
    this.write(LogLevel.warn, format, ...args);
  }

  public info(format: string, ...args: any[]) {
    this.write(LogLevel.info, format, ...args);
  }

  public debug(format: string, ...args: any[]) {
    this.write(LogLevel.debug, format, ...args);
  }

  public error(format: string, ...args: any[]) {
    this.write(LogLevel.error, format, ...args);
  }

  public write(logLevel: LogLevel, format: string, ...args: any[]) {
    const message = formatLogRecord(logLevel, format, ...args);

    this.writeRaw(logLevel, message);
  }

  public writeRaw(logLevel: LogLevel, rawMessage: string) {
    for (const transport of this.transports) {
      transport.write(logLevel, rawMessage);
    }
  }
}


function formatLogRecord(logLevel: LogLevel, messageFormat: string, ...args: any[]) {
  const date = new Date();

  let message: string;
  try {
    message = vsprintf(messageFormat, args);
  } catch {
    message = `[INVALID_FORMAT] ${messageFormat}`;
  }

  try {
    return sprintf(DEFAULT_LOG_FORMAT, {
      year: date.getFullYear(),
      month: date.getMonth() + 1,
      day: date.getDate(),
      hour: date.getHours(),
      minute: date.getMinutes(),
      seconds: date.getSeconds(),
      millis: date.getMilliseconds(),
      level: LogLevel[logLevel],
      message
    });
  } catch (error) {
    return `[INVALID_DATE_FORMAT] ${message}`;
  }
}

export class IpcLogger implements ILogger {
  constructor(private channel: string = DEFAULT_IPC_LOGGER) {}

  public write(logLevel: LogLevel, message: string) {
    ipcRenderer.send(this.channel, logLevel, message);
  }
}

export class IpcLoggerSource {
  constructor(private logger: Log, private channel: string = DEFAULT_IPC_LOGGER) {
    ipcMain.on(channel, this.onLogMessage);
  }

  public dispose() {
    ipcMain.removeListener(this.channel, this.onLogMessage);
  }

  private onLogMessage = (_event: Electron.IpcMessageEvent, logLevel: LogLevel, message: string) => {
    // Use writeRaw here because passing complex objects via IPC is impossible
    // Thus all messages coming through IPC are expected to be pre-formatted.
    this.logger.writeRaw(logLevel, message);
  };
}

export class ConsoleLogger implements ILogger {
  public write(logLevel: LogLevel, message: string) {
    switch (logLevel) {
      case LogLevel.debug:
        console.debug(message);
        break;

      case LogLevel.error:
        console.error(message);
        break;

      case LogLevel.info:
        console.info(message);
        break;

      case LogLevel.warn:
        console.warn(message);
        break;
    }
  }
}

export class FileLogger implements ILogger {
  get oldLogFilePath(): string | undefined {
    return this.oldLogFilePathValue;
  }
  private fsOpenPromise?: Promise<number>;
  private oldLogFilePathValue?: string;

  constructor(private logFilePath: string) {}

  public open(): Promise<void> {
    this.fsOpenPromise = this.backupOldLog().then(() => {
      return fsOpen(this.logFilePath, 'w');
    });

    return this.fsOpenPromise.then(() => Promise.resolve());
  }

  public async write(_logLevel: LogLevel, message: string) {
    if (!this.fsOpenPromise) {
      throw Error('You forgot to call FileLogger.open');
    }

    try {
      const fd = await this.fsOpenPromise;

      await fsWrite(fd, message + "\n", undefined, 'utf8');
    } catch (error) {
      // TODO: handle failure?
      console.error(`Unable to write to file: ${error.message}`);
    }
  }

  private async backupOldLog() {
    const logDirectory = path.dirname(this.logFilePath);
    const logFileExt = path.extname(this.logFilePath);
    const logFileName = path.basename(this.logFilePath, logFileExt);
    const oldLogFilePath = path.join(logDirectory, `${logFileName}.old${logFileExt}`);

    // Backup previous log file if it exists
    try {
      await fsAccess(this.logFilePath);
      await fsRename(this.logFilePath, oldLogFilePath);

      this.oldLogFilePathValue = oldLogFilePath;
    } catch (error) {
      // No previous log file exists
    }
  }
}

export default new Log();
