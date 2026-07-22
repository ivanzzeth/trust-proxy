import * as React from 'react';

import * as connAPI from '~/api/connections';
import prettyBytes from '~/misc/pretty-bytes';
import { ClashAPIConfig } from '~/types';

const { useCallback, useEffect, useState } = React;

export function useConnectionSummary(apiConfig: ClashAPIConfig) {
  const [state, setState] = useState({
    upTotal: '0 B',
    dlTotal: '0 B',
    connNumber: 0,
    mUsage: '0 B',
  });

  const read = useCallback(
    ({ downloadTotal, uploadTotal, connections, memory }) => {
      setState({
        upTotal: prettyBytes(uploadTotal),
        dlTotal: prettyBytes(downloadTotal),
        connNumber: connections ? connections.length : 0,
        mUsage: prettyBytes(memory),
      });
    },
    [setState]
  );

  useEffect(() => {
    return connAPI.fetchData(apiConfig, read, () => {
      /* noop */
    });
  }, [apiConfig, read]);

  return state;
}
