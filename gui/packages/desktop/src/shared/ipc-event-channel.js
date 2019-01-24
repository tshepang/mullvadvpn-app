// @flow

import { ipcMain, ipcRenderer } from 'electron';
import type { WebContents, IpcMainEvent, IpcRendererEvent } from 'electron';
import uuid from 'uuid';

import type { GuiSettingsState } from './gui-settings-state';

import type { AppUpgradeInfo, CurrentAppVersionInfo } from '../main/index';
import type {
  AccountToken,
  AccountData,
  Location,
  RelayList,
  RelaySettingsUpdate,
  Settings,
  TunnelStateTransition,
} from './daemon-rpc-types';

export type AppStateSnapshot = {
  isConnected: boolean,
  autoStart: boolean,
  tunnelState: TunnelStateTransition,
  settings: Settings,
  location: ?Location,
  relays: RelayList,
  currentVersion: CurrentAppVersionInfo,
  upgradeVersion: AppUpgradeInfo,
  guiSettings: GuiSettingsState,
};

interface Sender<T> {
  notify(webContents: WebContents, newState: T): void;
}

interface Receiver<T> {
  listen<T>(fn: (T) => void): void;
}

interface TunnelMethods {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
}

interface TunnelHandlers {
  handleConnect(fn: () => Promise<void>): void;
  handleDisconnect(fn: () => Promise<void>): void;
}

interface SettingsMethods {
  setAllowLan(boolean): Promise<void>;
  setEnableIpv6(boolean): Promise<void>;
  setBlockWhenDisconnected(boolean): Promise<void>;
  setOpenVpnMssfix(?number): Promise<void>;
  updateRelaySettings(update: RelaySettingsUpdate): Promise<void>;
}

interface SettingsHandlers {
  handleAllowLan(fn: (boolean) => Promise<void>): void;
  handleEnableIpv6(fn: (boolean) => Promise<void>): void;
  handleBlockWhenDisconnected(fn: (boolean) => Promise<void>): void;
  handleOpenVpnMssfix(fn: (?number) => Promise<void>): void;
  handleUpdateRelaySettings(fn: (RelaySettingsUpdate) => Promise<void>): void;
}

interface GuiSettingsMethods {
  setAutoConnect(boolean): void;
  setStartMinimized(boolean): void;
  setMonochromaticIcon(boolean): void;
}

interface GuiSettingsHandlers {
  handleAutoConnect((boolean) => void): void;
  handleStartMinimized((boolean) => void): void;
  handleMonochromaticIcon((boolean) => void): void;
}

interface AccountHandlers {
  handleSet(fn: (AccountToken) => Promise<void>): void;
  handleUnset(fn: () => Promise<void>): void;
  handleGetData(fn: (AccountToken) => Promise<AccountData>): void;
}

interface AccountMethods {
  set(token: AccountToken): Promise<void>;
  unset(): Promise<void>;
  getData(token: AccountToken): Promise<AccountData>;
}

interface AccountHistoryHandlers {
  handleGet(fn: () => Promise<Array<AccountToken>>): void;
  handleRemoveItem(fn: (token: AccountToken) => Promise<void>): void;
}

interface AccountHistoryMethods {
  get(): Promise<Array<AccountToken>>;
  removeItem(token: AccountToken): Promise<void>;
}

interface AutoStartMethods {
  listen(fn: (boolean) => void): void;
  set(autoStart: boolean): Promise<void>;
}

interface AutoStartHandlers {
  handleSet((boolean) => Promise<void>): void;
}

/// Events names

const DAEMON_CONNECTED = 'daemon-connected';
const DAEMON_DISCONNECTED = 'daemon-disconnected';

const TUNNEL_STATE_CHANGED = 'tunnel-state-changed';
const CONNECT_TUNNEL = 'connect-tunnel';
const DISCONNECT_TUNNEL = 'disconnect-tunnel';

const SETTINGS_CHANGED = 'settings-changed';
const SET_ALLOW_LAN = 'set-allow-lan';
const SET_ENABLE_IPV6 = 'set-enable-ipv6';
const SET_BLOCK_WHEN_DISCONNECTED = 'set-block-when-disconnected';
const SET_OPENVPN_MSSFIX = 'set-openvpn-mssfix';
const UPDATE_RELAY_SETTINGS = 'update-relay-settings';

const LOCATION_CHANGED = 'location-changed';
const RELAYS_CHANGED = 'relays-changed';
const CURRENT_VERSION_CHANGED = 'current-version-changed';
const UPGRADE_VERSION_CHANGED = 'upgrade-version-changed';

const GUI_SETTINGS_CHANGED = 'gui-settings-changed';
const SET_AUTO_CONNECT = 'set-auto-connect';
const SET_MONOCHROMATIC_ICON = 'set-monochromatic-icon';
const SET_START_MINIMIZED = 'set-start-minimized';

const GET_APP_STATE = 'get-app-state';

const GET_ACCOUNT_HISTORY = 'get-account-history';
const REMOVE_ACCOUNT_HISTORY_ITEM = 'remove-account-history-item';

const SET_ACCOUNT = 'set-account';
const UNSET_ACCOUNT = 'unset-account';
const GET_ACCOUNT_DATA = 'get-account-data';

const AUTO_START_CHANGED = 'auto-start-changed';
const SET_AUTO_START = 'set-auto-start';

/// Typed IPC event channel
///
/// Static methods are meant to be provide the way to send the events from a renderer process, while
/// instance methods are meant to be used from a main process.
///
export class IpcRendererEventChannel {
  static state = {
    /// Synchronously sends the IPC request and returns the app state snapshot
    get(): AppStateSnapshot {
      return ipcRenderer.sendSync(GET_APP_STATE);
    },
  };

  static daemonConnected: Receiver<void> = {
    listen: listen(DAEMON_CONNECTED),
  };

  static daemonDisconnected: Receiver<?string> = {
    listen: listen(DAEMON_DISCONNECTED),
  };

  static tunnel: Receiver<TunnelStateTransition> & TunnelMethods = {
    listen: listen(TUNNEL_STATE_CHANGED),
    connect: requestSender(CONNECT_TUNNEL),
    disconnect: requestSender(DISCONNECT_TUNNEL),
  };

  static settings: Receiver<Settings> & SettingsMethods = {
    listen: listen(SETTINGS_CHANGED),
    setAllowLan: requestSender(SET_ALLOW_LAN),
    setEnableIpv6: requestSender(SET_ENABLE_IPV6),
    setBlockWhenDisconnected: requestSender(SET_BLOCK_WHEN_DISCONNECTED),
    setOpenVpnMssfix: requestSender(SET_OPENVPN_MSSFIX),
    updateRelaySettings: requestSender(UPDATE_RELAY_SETTINGS),
  };

  static location: Receiver<Location> = {
    listen: listen(LOCATION_CHANGED),
  };

  static relays: Receiver<RelayList> = {
    listen: listen(RELAYS_CHANGED),
  };

  static currentVersion: Receiver<CurrentAppVersionInfo> = {
    listen: listen(CURRENT_VERSION_CHANGED),
  };

  static upgradeVersion: Receiver<AppUpgradeInfo> = {
    listen: listen(UPGRADE_VERSION_CHANGED),
  };

  static guiSettings: Receiver<GuiSettingsState> & GuiSettingsMethods = {
    listen: listen(GUI_SETTINGS_CHANGED),
    setAutoConnect: set(SET_AUTO_CONNECT),
    setMonochromaticIcon: set(SET_MONOCHROMATIC_ICON),
    setStartMinimized: set(SET_START_MINIMIZED),
  };

  static autoStart: Receiver<boolean> & AutoStartMethods = {
    listen: listen(AUTO_START_CHANGED),
    set: requestSender(SET_AUTO_START),
  };

  static account: AccountMethods = {
    set: requestSender(SET_ACCOUNT),
    unset: requestSender(UNSET_ACCOUNT),
    getData: requestSender(GET_ACCOUNT_DATA),
  };

  static accountHistory: AccountHistoryMethods = {
    get: requestSender(GET_ACCOUNT_HISTORY),
    removeItem: requestSender(REMOVE_ACCOUNT_HISTORY_ITEM),
  };
}

export class IpcMainEventChannel {
  static state = {
    handleGet(fn: () => AppStateSnapshot) {
      ipcMain.on(GET_APP_STATE, (event) => {
        event.returnValue = fn();
      });
    },
  };

  static daemonConnected: Sender<void> = {
    notify: sender(DAEMON_CONNECTED),
  };

  static daemonDisconnected: Sender<?string> = {
    notify: sender(DAEMON_DISCONNECTED),
  };

  static tunnel: Sender<TunnelStateTransition> & TunnelHandlers = {
    notify: sender(TUNNEL_STATE_CHANGED),
    handleConnect: requestHandler(CONNECT_TUNNEL),
    handleDisconnect: requestHandler(DISCONNECT_TUNNEL),
  };

  static location: Sender<Location> = {
    notify: sender(LOCATION_CHANGED),
  };

  static settings: Sender<Settings> & SettingsHandlers = {
    notify: sender(SETTINGS_CHANGED),
    handleAllowLan: requestHandler(SET_ALLOW_LAN),
    handleEnableIpv6: requestHandler(SET_ENABLE_IPV6),
    handleBlockWhenDisconnected: requestHandler(SET_BLOCK_WHEN_DISCONNECTED),
    handleOpenVpnMssfix: requestHandler(SET_OPENVPN_MSSFIX),
    handleUpdateRelaySettings: requestHandler(UPDATE_RELAY_SETTINGS),
  };

  static relays: Sender<RelayList> = {
    notify: sender(RELAYS_CHANGED),
  };

  static currentVersion: Sender<CurrentAppVersionInfo> = {
    notify: sender(CURRENT_VERSION_CHANGED),
  };

  static upgradeVersion: Sender<AppUpgradeInfo> = {
    notify: sender(UPGRADE_VERSION_CHANGED),
  };

  static guiSettings: Sender<GuiSettingsState> & GuiSettingsHandlers = {
    notify: sender(GUI_SETTINGS_CHANGED),
    handleAutoConnect: handler(SET_AUTO_CONNECT),
    handleMonochromaticIcon: handler(SET_MONOCHROMATIC_ICON),
    handleStartMinimized: handler(SET_START_MINIMIZED),
  };

  static autoStart: Sender<boolean> & AutoStartHandlers = {
    notify: sender(AUTO_START_CHANGED),
    handleSet: requestHandler(SET_AUTO_START),
  };

  static account: AccountHandlers = {
    handleSet: requestHandler(SET_ACCOUNT),
    handleUnset: requestHandler(UNSET_ACCOUNT),
    handleGetData: requestHandler(GET_ACCOUNT_DATA),
  };

  static accountHistory: AccountHistoryHandlers = {
    handleGet: requestHandler(GET_ACCOUNT_HISTORY),
    handleRemoveItem: requestHandler(REMOVE_ACCOUNT_HISTORY_ITEM),
  };
}

function listen<T>(event: string): ((T) => void) => void {
  return function(fn: (T) => void) {
    ipcRenderer.on(event, (_, newState: T) => fn(newState));
  };
}

function set<T>(event: string): (T) => void {
  return function(newValue: T) {
    ipcRenderer.send(event, newValue);
  };
}

function sender<T>(event: string): (WebContents, T) => void {
  return function(webContents: WebContents, newState: T) {
    webContents.send(event, newState);
  };
}

function handler<T>(event: string): ((T) => void) => void {
  return function(handlerFn: (T) => void) {
    ipcMain.on(event, (_, newValue: T) => {
      handlerFn(newValue);
    });
  };
}

type RequestResult<T> = { type: 'success', value: T } | { type: 'error', message: string };

function requestHandler<T>(event: string): (fn: (...args: Array<any>) => Promise<T>) => void {
  return function(fn: (...args: Array<any>) => Promise<T>) {
    ipcMain.on(event, async (ipcEvent: IpcMainEvent, requestId: string, ...args: Array<any>) => {
      const sender = ipcEvent.sender;
      const responseEvent = `${event}-${requestId}`;
      try {
        const result: RequestResult<T> = { type: 'success', value: await fn(...args) };

        sender.send(responseEvent, result);
      } catch (error) {
        const result: RequestResult<T> = { type: 'error', message: error.message || '' };

        sender.send(responseEvent, result);
      }
    });
  };
}

function requestSender<T>(event: string): (...args: Array<any>) => Promise<T> {
  return function(...args: Array<any>): Promise<T> {
    return new Promise((resolve: (result: T) => void, reject: (error: Error) => void) => {
      const requestId = uuid.v4();
      const responseEvent = `${event}-${requestId}`;

      ipcRenderer.once(responseEvent, (_ipcEvent: IpcRendererEvent, result: RequestResult<T>) => {
        switch (result.type) {
          case 'error':
            reject(new Error(result.message));
            break;

          case 'success':
            resolve(result.value);
            break;
        }
      });

      ipcRenderer.send(event, requestId, ...args);
    });
  };
}