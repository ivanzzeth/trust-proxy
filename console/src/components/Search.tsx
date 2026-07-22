import debounce from 'lodash-es/debounce';
import React, { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import s0 from './Search.module.scss';

function RuleSearch({ dispatch, searchText, updateSearchText, className }) {
  const { t } = useTranslation();
  const [text, setText] = useState(searchText);
  const updateSearchTextInternal = useCallback(
    (v) => {
      dispatch(updateSearchText(v));
    },
    [dispatch, updateSearchText]
  );
  const updateSearchTextDebounced = useMemo(
    () => debounce(updateSearchTextInternal, 300),
    [updateSearchTextInternal]
  );
  const onChange = (e) => {
    setText(e.target.value);
    updateSearchTextDebounced(e.target.value);
  };

  return (
    <div className={className || s0.RuleSearch}>
      <input
        type="text"
        value={text}
        onChange={onChange}
        className={s0.input}
        placeholder={t('Search')}
      />
    </div>
  );
}

export default RuleSearch;
