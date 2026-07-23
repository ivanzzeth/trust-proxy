export default {
  en: {
    title: 'Rules',
    description: 'Active route rules on the data plane (via the Clash API). Read-only; edit routing through the whitelist and rule sets.',
    columnType: 'Type',
    columnPayload: 'Payload',
    columnProxy: 'Proxy',
    empty: 'No rules',
  },
  zh: {
    title: '规则',
    description: '数据面当前生效的路由规则（经 Clash API 读取）。只读；如需调整路由请通过白名单与规则集。',
    columnType: '类型',
    columnPayload: '匹配内容',
    columnProxy: '出站',
    empty: '暂无规则',
  },
};
