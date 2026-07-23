export default {
  en: {
    title: 'Proxies',
    description:
      'Outbound groups and their nodes (via the Clash API). The gateway\'s whitelisted traffic exits through the “proxy” group.',
    emptyGroups: 'No proxy groups. Apply a subscription under Nodes first.',
    nowLabel: 'now:',
    test: 'Test',
    delayTimeout: 'timeout',
    footerHint: 'URLTest groups auto-select the lowest-latency node; Selector groups let you pin one.',
  },
  zh: {
    title: '代理',
    description:
      '出站组及其节点（通过 Clash API）。网关放行的流量经 “proxy” 组出网。',
    emptyGroups: '暂无代理组，请先在“节点”页应用订阅。',
    nowLabel: '当前:',
    test: '测速',
    delayTimeout: '超时',
    footerHint: 'URLTest 组自动选择延迟最低的节点；Selector 组可手动指定。',
  },
};
