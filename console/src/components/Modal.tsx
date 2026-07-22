import cx from 'clsx';
import * as React from 'react';
import ReactModalBase, { Props as ReactModalProps } from 'react-modal';

import s0 from './Modal.module.scss';

type Props = ReactModalProps & {
  isOpen: boolean;
  onRequestClose: (...args: any[]) => any;
  children: React.ReactNode;
};

const ReactModal = ReactModalBase as unknown as React.ComponentType<ReactModalProps>;

function withBaseClass(
  className: ReactModalProps['className'],
  baseClassName: string
): ReactModalProps['className'] {
  if (!className) {
    return baseClassName;
  }

  if (typeof className === 'string') {
    return cx(className, baseClassName);
  }

  return {
    ...className,
    base: cx(className.base, baseClassName),
  };
}

function ModalAPIConfig({
  isOpen,
  onRequestClose,
  className,
  overlayClassName,
  children,
  ...otherProps
}: Props) {
  const contentCls = withBaseClass(className, s0.content);
  const overlayCls = withBaseClass(overlayClassName, s0.overlay);
  return (
    <ReactModal
      isOpen={isOpen}
      onRequestClose={onRequestClose}
      className={contentCls}
      overlayClassName={overlayCls}
      {...otherProps}
    >
      {children}
    </ReactModal>
  );
}

export default React.memo(ModalAPIConfig);
