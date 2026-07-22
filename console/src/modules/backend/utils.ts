import { fetchConfigs } from '~/api/configs';
import type { ClashAPIConfig } from '~/types';

export const DEFAULT_API_BASE_URL = 'http://127.0.0.1:9090';

const Ok = 0;

export function normalizeAPIBaseURL(baseURL: string, currentProtocol: string) {
  let normalizedBaseURL = baseURL || DEFAULT_API_BASE_URL;

  if (normalizedBaseURL) {
    const prefix = normalizedBaseURL.substring(0, 7);
    if (prefix.includes(':/')) {
      if (prefix !== 'http://' && prefix !== 'https:/') {
        return { error: 'Must starts with http:// or https://' };
      }
    } else if (currentProtocol) {
      normalizedBaseURL = `${currentProtocol}//${normalizedBaseURL}`;
    }
  }

  return { baseURL: normalizedBaseURL };
}

export async function verifyAPIConfig(apiConfig: ClashAPIConfig): Promise<[number, string?]> {
  try {
    new URL(apiConfig.baseURL);
  } catch (e) {
    if (apiConfig.baseURL) {
      const prefix = apiConfig.baseURL.substring(0, 7);
      if (prefix !== 'http://' && prefix !== 'https:/') {
        return [1, 'Must starts with http:// or https://'];
      }
    }

    return [1, 'Invalid URL'];
  }

  try {
    const res = await fetchConfigs(apiConfig);
    if (res.status > 399) {
      return [1, res.statusText];
    }
    return [Ok];
  } catch (e) {
    return [1, 'Failed to connect'];
  }
}

export async function detectEmbeddedAPIBaseURL() {
  try {
    const res = await fetch('/');
    if (res.headers.get('content-type')?.includes('application/json')) {
      const data = await res.json();
      if (data.hello === 'clash') {
        return window.location.origin;
      }
    }
  } catch (e) {
    // ignore auto detection failures
  }

  return null;
}
