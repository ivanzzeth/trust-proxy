import { LazyMotion, domAnimation, m } from 'framer-motion';
import React from 'react';

const { memo } = React;

const variantsCollpapsibleWrap = {
  initialOpen: {
    height: 'auto',
    opacity: 1,
    visibility: 'visible',
    transition: { duration: 0 },
  },
  open: {
    height: 'auto',
    opacity: 1,
    visibility: 'visible',
    transition: { duration: 0.3 },
  },
  closed: {
    height: 0,
    opacity: 0,
    visibility: 'hidden',
    overflowY: 'hidden',
    transition: { duration: 0.3 },
  },
};

const Collapsible = memo(({ children, isOpen }: { children: React.ReactNode; isOpen: boolean }) => {
  return (
    <LazyMotion features={domAnimation}>
      <m.div
        initial={isOpen ? 'initialOpen' : 'closed'}
        animate={isOpen ? 'open' : 'closed'}
        variants={variantsCollpapsibleWrap}
        style={{ overflow: 'hidden' }}
      >
        {children}
      </m.div>
    </LazyMotion>
  );
});

export default Collapsible;
