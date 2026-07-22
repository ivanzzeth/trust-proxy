export type SelectOption = [string, string];
export type PortField = {
  key: string;
  label: string;
};

export const CONFIG_CHART_STYLE_PROPS = [{ id: 0 }, { id: 1 }, { id: 2 }, { id: 3 }];

export const LOG_LEVEL_OPTIONS: SelectOption[] = [
  ['debug', 'Debug'],
  ['info', 'Info'],
  ['warning', 'Warning'],
  ['error', 'Error'],
  ['silent', 'Silent'],
];

export const PORT_FIELDS: PortField[] = [
  { key: 'port', label: 'Http Port' },
  { key: 'socks-port', label: 'Socks5 Port' },
  { key: 'mixed-port', label: 'Mixed Port' },
  { key: 'redir-port', label: 'Redir Port' },
  { key: 'mitm-port', label: 'MITM Port' },
];

export const LANGUAGE_OPTIONS: SelectOption[] = [
  ['zh-cn', '简体中文'],
  ['zh-tw', '繁體中文'],
  ['en', 'English'],
  ['vi', 'Vietnamese'],
  ['ru', 'Русский'],
];

export const MODE_OPTIONS: SelectOption[] = [
  ['direct', 'Direct'],
  ['rule', 'Rule'],
  ['script', 'Script'],
  ['global', 'Global'],
];

export const TUN_STACK_OPTIONS: SelectOption[] = [
  ['gvisor', 'gVisor'],
  ['mixed', 'Mixed'],
  ['system', 'System'],
];

export function getBackendContent(version: { meta?: boolean; premium?: boolean } | undefined) {
  if (version?.meta && !version?.premium) {
    return 'Clash.Meta ';
  }
  if (version?.meta && version?.premium) {
    return 'sing-box ';
  }
  return 'Clash Premium';
}
