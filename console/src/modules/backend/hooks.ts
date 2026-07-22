import * as React from 'react';

import { fetchConfigs } from '~/store/configs';
import { closeModal } from '~/store/modals';
import type { DispatchFn } from '~/store/types';
import type { ClashAPIConfig } from '~/types';

import { detectEmbeddedAPIBaseURL, normalizeAPIBaseURL, verifyAPIConfig } from './utils';

const { useCallback, useEffect, useState } = React;

export function useBackendConfigForm({
  onAddConfig,
}: {
  onAddConfig: (config: ClashAPIConfig) => void;
}) {
  const [baseURL, setBaseURL] = useState('');
  const [secret, setSecret] = useState('');
  const [errMsg, setErrMsg] = useState('');

  const handleInputOnChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setErrMsg('');
    const target = e.target;
    const { name, value } = target;

    switch (name) {
      case 'baseURL':
        setBaseURL(value);
        break;
      case 'secret':
        setSecret(value);
        break;
      default:
        throw new Error(`unknown input name ${name}`);
    }
  }, []);

  const onConfirm = useCallback(() => {
    const normalizedResult = normalizeAPIBaseURL(baseURL, window.location.protocol);
    if ('error' in normalizedResult) {
      setErrMsg(normalizedResult.error);
      return;
    }

    const nextConfig = { baseURL: normalizedResult.baseURL, secret };
    verifyAPIConfig(nextConfig).then(([status, message]) => {
      if (status !== 0) {
        setErrMsg(message ?? 'Failed to connect');
        return;
      }

      onAddConfig(nextConfig);
    });
  }, [baseURL, onAddConfig, secret]);

  const handleContentOnKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (
        e.target instanceof Element &&
        (!e.target.tagName || e.target.tagName.toUpperCase() !== 'INPUT')
      ) {
        return;
      }

      if (e.key !== 'Enter') return;

      onConfirm();
    },
    [onConfirm]
  );

  useEffect(() => {
    let isCancelled = false;

    detectEmbeddedAPIBaseURL().then((detectedBaseURL) => {
      if (!isCancelled && detectedBaseURL) {
        setBaseURL(detectedBaseURL);
      }
    });

    return () => {
      isCancelled = true;
    };
  }, []);

  return {
    baseURL,
    secret,
    errMsg,
    handleInputOnChange,
    handleContentOnKeyDown,
    onConfirm,
  };
}

export function useBackendDiscovery({
  apiConfig,
  dispatch,
}: {
  apiConfig: ClashAPIConfig;
  dispatch: DispatchFn;
}) {
  const closeAPIConfigModal = useCallback(() => {
    dispatch(closeModal('apiConfig'));
  }, [dispatch]);

  useEffect(() => {
    dispatch(fetchConfigs(apiConfig));
  }, [apiConfig, dispatch]);

  return {
    closeAPIConfigModal,
  };
}
