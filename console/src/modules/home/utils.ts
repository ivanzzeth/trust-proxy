import prettyBytes from '~/misc/pretty-bytes';

export function formatTrafficRate(value: number) {
  return `${prettyBytes(value || 0)}/s`;
}
