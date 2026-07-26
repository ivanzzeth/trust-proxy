export default {
  en: {
    title: 'Profiles',
    description:
      'Save the whole egress policy as a named snapshot and switch back to it in one click. A profile captures Permit / Deny / No-proxy lists, custom rules & packs, rule sets, proxy groups, DNS and capture mode, plus the applied subscription — not TUN options, inbound auth or VPN endpoints.',
    namePlaceholder: 'profile name',
    saveCurrent: 'Save current policy',
    profileSaved: 'Saved — activate it any time to come back to this policy',
    profileActivated: 'Profile activated — the policy has been replaced',
    active: 'active',

    currentTitle: 'Current policy',
    currentHint: 'This is what “Save current policy” captures right now.',
    saveHint: 'Names are unique: saving under an existing name overwrites it.',
    overwriteConfirm: 'A profile named “{{name}}” already exists. Overwrite it with the current policy?',
    activateConfirm:
      'Activating “{{name}}” REPLACES the entire current policy (Permit / Deny / No-proxy / rules / rule sets / groups / DNS / mode) in one rebuild. Continue?',
    activateNoBackup:
      'The current policy is not saved anywhere, so this cannot be undone. Save it as a profile first — then activate.',
    deleteConfirm: 'Delete profile “{{name}}”? The policy running right now is not affected.',

    howTitle: 'How profiles work',
    how1: 'Build your policy on the Policy / Rules / DNS / Proxies pages — those pages are the source of truth.',
    how2: 'Come back here and save it under a name (“home”, “office”, “locked-down”).',
    how3: 'Activating a profile replaces the whole policy at once, so keep a snapshot of the current one as your way back.',

    statPermit: 'Permit',
    statDeny: 'Deny',
    statDirectlist: 'No-proxy',
    statCustomRules: 'Custom rules',
    statRuleSets: 'Rule sets',
    statProxyGroups: 'Custom groups',
    statDNS: 'DNS servers',
    statMode: 'Capture mode',
    statPosture: 'Posture',
    statSub: 'Subscription',
    permitStat: '{{domains}} domains · {{ips}} IPs',
    notCaptured: 'not captured',
    activate: 'Activate',
  },
  zh: {
    title: '配置档',
    description:
      '把整套出网策略存成一份命名快照，之后一键切回。一份配置档包含：Permit / Deny / 免代理名单、自定义规则与策略包、规则集、代理分组、DNS、抓包模式，以及当时启用的订阅；不含 TUN 选项、入站鉴权、VPN 端点。',
    namePlaceholder: '配置档名称',
    saveCurrent: '保存当前策略',
    profileSaved: '已保存 — 之后随时激活即可回到这套策略',
    profileActivated: '配置档已激活 — 策略已被整份替换',
    active: '已激活',

    currentTitle: '当前策略',
    currentHint: '这就是点「保存当前策略」会抓下来的内容。',
    saveHint: '名称唯一：用已有名称保存会覆盖那一份。',
    overwriteConfirm: '已存在名为「{{name}}」的配置档，用当前策略覆盖它？',
    activateConfirm:
      '激活「{{name}}」会把当前整套策略（Permit / Deny / 免代理 / 规则 / 规则集 / 分组 / DNS / 模式）一次性替换掉。继续？',
    activateNoBackup: '当前策略还没存成配置档，这一步无法回退。请先保存当前策略，再激活。',
    deleteConfirm: '删除配置档「{{name}}」？不影响正在运行的策略。',

    howTitle: '配置档怎么用',
    how1: '先在「策略 / 路由规则 / DNS / 代理组」等页面配好策略 —— 那些页面才是策略的来源。',
    how2: '回到这里，给这套策略起个名字保存（比如「家里」「公司」「最严」）。',
    how3: '激活某份配置档＝把整套策略一次性换掉，所以先给当前策略存一份，作为回退的路。',

    statPermit: 'Permit 许可',
    statDeny: 'Deny 拒绝',
    statDirectlist: '免代理',
    statCustomRules: '自定义规则',
    statRuleSets: '规则集',
    statProxyGroups: '自定义分组',
    statDNS: 'DNS 服务器',
    statMode: '抓包模式',
    statPosture: '姿势',
    statSub: '订阅',
    permitStat: '{{domains}} 个域名 · {{ips}} 个 IP',
    notCaptured: '未捕获',
    activate: '激活',
  },
};
